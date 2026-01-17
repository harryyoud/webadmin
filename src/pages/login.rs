/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use gloo_storage::{LocalStorage, SessionStorage, Storage};
use leptos::*;
use leptos_meta::*;
use leptos_router::{use_navigate, use_query_map, Url};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::{Deserialize, Serialize};

use crate::{
    components::{
        form::{
            input::{InputPassword, InputText},
            FormElement,
        },
        messages::alert::{use_alerts, Alert, Alerts},
    },
    core::{
        oauth::{
            extern_oauth_resolve, oauth_authenticate, AuthenticationResult, Credentials,
            ExternOAuthResponse, OAuthIdToken, OAUTH_AUTHORIZE_URL, OAUTH_CLIENT_ID,
        },
        schema::{Builder, Schemas, Transformer, Type, Validator},
        AccessToken, Permissions,
    },
    STATE_LOGIN_NAME_KEY, STATE_STORAGE_KEY,
};

const STATE_OAUTH_KEY: &str = "webadmin_oauth_state";
const STATE_OAUTH_BASE_URL: &str = "webadmin_oauth_base_url";

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SavedSession {
    login: String,
    base_url: String,
}

#[component]
pub fn Login() -> impl IntoView {
    let stored_data: Option<SavedSession> = LocalStorage::get(STATE_LOGIN_NAME_KEY).ok();
    let remember_me = create_rw_signal(stored_data.is_some());
    let show_totp = create_rw_signal(false);
    let alert = use_alerts();
    let auth_token = use_context::<RwSignal<AccessToken>>().unwrap();
    let query = use_query_map();

    let oauth_state: Option<String> = SessionStorage::get(STATE_OAUTH_KEY).ok();
    let oauth_base_url: Option<String> = SessionStorage::get(STATE_OAUTH_BASE_URL).ok();
    let callback_url = {
        // we need the absolute URL to the login page
        let url = Url::try_from(document().document_uri().unwrap().as_str()).unwrap();
        StoredValue::new(format!("{}/login", url.origin))
    };
    let loading = create_rw_signal(false);

    let login_action = create_action(
        move |(username, password, base_url, oidc): &(String, String, String, bool)| {
            loading.set(true);
            SessionStorage::delete(STATE_OAUTH_KEY);
            SessionStorage::delete(STATE_OAUTH_BASE_URL);

            let mut username = username.clone();
            let password = password.clone();
            let base_url = base_url.clone();
            let oidc = oidc.clone();
            let callback_url = callback_url.clone();

            async move {
                let credentials = match (oidc, query.get_untracked().get("code").cloned()) {
                    (true, Some(code)) => {
                        match extern_oauth_resolve(&code, callback_url.get_value().as_str()).await {
                            ExternOAuthResponse::Granted(stalwart_token) => Credentials::OAuth2 {
                                token: stalwart_token.access_token,
                            },
                            ExternOAuthResponse::Error { error } => {
                                alert.set(Alert::error(format!("Failed to obtain OIDC token from authorization server: {error}")));
                                loading.set(false);
                                return;
                            }
                        }
                    }
                    (true, None) => {
                        alert.set(Alert::error(
                            "No code returned from authorization server".to_string(),
                        ));
                        loading.set(false);
                        return;
                    }
                    (false, _) => Credentials::UsernamePassword {
                        username: username.clone(),
                        password,
                    },
                };
                match oauth_authenticate(&base_url, &credentials).await {
                    AuthenticationResult::Success(response) => {
                        let permissions = Permissions::new(response.permissions);
                        let default_url = permissions.default_url(response.is_enterprise);

                        if default_url.is_empty() {
                            alert.set(Alert::error(
                                "You are not authorized to access this service.",
                            ));
                            loading.set(false);
                            return;
                        }

                        if username.is_empty() {
                            if let Ok(token_username) = response
                                .grant
                                .id_token
                                .ok_or(())
                                .and_then(|x| x.split('.').nth(1).map(str::to_string).ok_or(()))
                                .and_then(|x| STANDARD_NO_PAD.decode(x).map_err(|_| ()))
                                .and_then(|x| String::from_utf8(x).map_err(|_| ()))
                                .and_then(|x| {
                                    serde_json::from_str::<OAuthIdToken>(&x).map_err(|_| ())
                                })
                                .map(|x| x.preferred_username)
                            {
                                username = token_username;
                            };
                        }

                        let refresh_token = response.grant.refresh_token.unwrap_or_default();
                        auth_token.update(|auth_token| {
                            auth_token.access_token = response.grant.access_token.into();
                            auth_token.refresh_token = refresh_token.clone().into();
                            auth_token.base_url = base_url.clone().into();
                            auth_token.username = username.into();
                            auth_token.is_valid = true;
                            auth_token.permissions = permissions;
                            auth_token.is_enterprise = response.is_enterprise;

                            if let Err(err) =
                                SessionStorage::set(STATE_STORAGE_KEY, auth_token.clone())
                            {
                                log::error!("Failed to save state to session storage: {}", err);
                            }
                        });

                        // Set timer to refresh token
                        if response.grant.expires_in > 0 && !refresh_token.is_empty() {
                            log::debug!(
                                "Next OAuth token refresh in {} seconds.",
                                response.grant.expires_in
                            );

                            set_timeout(
                                move || {
                                    auth_token.update(|auth_token| {
                                        auth_token.is_valid = false;
                                    });
                                },
                                Duration::from_secs(response.grant.expires_in),
                            );
                        }

                        loading.set(false);
                        use_navigate()(default_url, Default::default());
                    }
                    AuthenticationResult::TotpRequired => {
                        loading.set(false);
                        show_totp.set(true);
                    }
                    AuthenticationResult::Error(err) => {
                        loading.set(false);
                        alert.set(err);
                    }
                }
            }
        },
    );

    // if we find code and state in query parameters, this is now the oauth2 callback
    if let Some(_) = query.get_untracked().get("code").cloned() {
        if oauth_state.is_some() && oauth_state == query.get_untracked().get("state").cloned() {
            login_action.dispatch((
                "".into(),
                "".into(),
                oauth_base_url.unwrap_or("".into()),
                true,
            ));
        } else {
            SessionStorage::delete(STATE_OAUTH_KEY);
            SessionStorage::delete(STATE_OAUTH_BASE_URL);
            alert.set(Alert::error(
                "Stale OAuth state parameter. Please try again",
            ));
            use_navigate()("/login", Default::default());
        }
    }

    let (login, base_url) = stored_data.map_or_else(
        || (String::new(), String::new()),
        |session| (session.login, session.base_url),
    );
    let data = expect_context::<Arc<Schemas>>()
        .build_form("login")
        .with_value("base-url", base_url)
        .with_value("login", login)
        .into_signal();
    let has_remote = create_memo(move |_| {
        (query.get().get("remote").is_some()
            || data
                .get()
                .get("base-url")
                .filter(|v| !v.is_empty())
                .is_some())
            && !show_totp.get()
    });

    view! {
        <Body class="dark:bg-slate-900 bg-gray-100 flex h-full items-center py-16"/>
        <main class="w-full max-w-md mx-auto p-6">
            <div class="mt-7 bg-white border border-gray-200 rounded-xl shadow-sm dark:bg-gray-800 dark:border-gray-700">
                <div class="p-4 sm:p-7">
                    <div class="text-center p-6">
                        <img src="/logo.svg"/>

                    </div>

                    <div class="mt-5">
                        <Alerts/>
                        <Show when=move || loading.get()>
                        <span>Logging in...</span>
                        </Show>
                        <Show when=move || !loading.get()>
                        <form on:submit=|ev| ev.prevent_default()>
                            <div class="grid gap-y-4">
                                <Show when=move || has_remote.get()>
                                    <div>
                                        <label class="block text-sm mb-2 dark:text-white">
                                            Host
                                        </label>
                                        <InputText
                                            placeholder="https://mail.example.org"
                                            element=FormElement::new("base-url", data)
                                        />
                                    </div>
                                </Show>
                                <Show when=move || !show_totp.get()>
                                    <div>
                                        <label class="block text-sm mb-2 dark:text-white">
                                            Login
                                        </label>
                                        <InputText
                                            placeholder="user@example.org"
                                            element=FormElement::new("login", data)
                                        />
                                    </div>
                                    <div>
                                        <div class="flex justify-between items-center">
                                            <label class="block text-sm mb-2 dark:text-white">
                                                Password
                                            </label>

                                        </div>
                                        <InputPassword element=FormElement::new("password", data)/>
                                    </div>
                                </Show>
                                <Show when=move || show_totp.get()>
                                    <div>
                                        <label class="block text-sm mb-2 dark:text-white">
                                            TOTP Token
                                        </label>
                                        <InputText element=FormElement::new("totp-code", data)/>
                                    </div>
                                </Show>
                                <div class="flex items-center">
                                    <div class="flex">
                                        <input
                                            id="remember-me"
                                            name="remember-me"
                                            type="checkbox"
                                            class="shrink-0 mt-0.5 border-gray-200 rounded text-blue-600 focus:ring-blue-500 dark:bg-gray-800 dark:border-gray-700 dark:checked:bg-blue-500 dark:checked:border-blue-500 dark:focus:ring-offset-gray-800"
                                            prop:checked=remember_me
                                            on:input=move |_| {
                                                remember_me
                                                    .update(|v| {
                                                        *v = !*v;
                                                    })
                                            }
                                        />

                                    </div>
                                    <div class="ms-3">
                                        <label for="remember-me" class="text-sm dark:text-white">
                                            Remember me
                                        </label>
                                    </div>
                                </div>

                                <button
                                    type="submit"
                                    class="w-full py-3 px-4 inline-flex justify-center items-center gap-x-2 text-sm font-semibold rounded-lg border border-transparent bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:pointer-events-none dark:focus:outline-none dark:focus:ring-1 dark:focus:ring-gray-600"
                                    on:click=move |_| {
                                        data.update(|data| {
                                            if data.validate_form() {
                                                let login = data
                                                    .value::<String>("login")
                                                    .unwrap_or_default();
                                                let password = match (
                                                    data.value::<String>("password").unwrap_or_default(),
                                                    data.value::<String>("totp-code"),
                                                ) {
                                                    (password, Some(totp)) => format!("{}${}", password, totp),
                                                    (password, None) => password,
                                                };
                                                let base_url = data
                                                    .value::<String>("base-url")
                                                    .unwrap_or_default();
                                                if remember_me.get() {
                                                    if let Err(err) = LocalStorage::set(
                                                        STATE_LOGIN_NAME_KEY,
                                                        SavedSession {
                                                            login: login.clone(),
                                                            base_url: base_url.clone(),
                                                        },
                                                    ) {
                                                        log::error!(
                                                            "Failed to save login name to local storage: {}", err
                                                        );
                                                    }
                                                } else {
                                                    LocalStorage::delete(STATE_LOGIN_NAME_KEY);
                                                }
                                                login_action.dispatch((login, password, base_url, false));
                                            }
                                        });
                                    }
                                >

                                    Sign in
                                </button>
                                <a
                                    rel="external"
                                    href="#"
                                    class="w-full py-3 px-4 inline-flex justify-center items-center gap-x-2 text-sm font-semibold rounded-lg border border-transparent bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:pointer-events-none dark:focus:outline-none dark:focus:ring-1 dark:focus:ring-gray-600"
                                    on:click=move |_| {
                                        data.update(|data| {
                                            let checks = data.schema.fields.get("base-url").unwrap().input_check(data).unwrap();
                                            let base_url = match checks.check_value(data.get("base-url").unwrap().into()) {
                                                Ok(base_url) => {
                                                    data.set("base-url", base_url.clone());
                                                    base_url
                                                },
                                                Err(err) => {
                                                    data.new_error("base-url", err);
                                                    return;
                                                },
                                            };
                                            if remember_me.get() {
                                                if let Err(err) = LocalStorage::set(
                                                    STATE_LOGIN_NAME_KEY,
                                                    SavedSession {
                                                        login: "".to_string(),
                                                        base_url: base_url.clone(),
                                                    },
                                                ) {
                                                    log::error!(
                                                        "Failed to save login name to local storage: {}", err
                                                    );
                                                }
                                            } else {
                                                LocalStorage::delete(STATE_LOGIN_NAME_KEY);
                                            }

                                            let new_oauth_state = thread_rng()
                                                .sample_iter(Alphanumeric)
                                                .take(16)
                                                .map(char::from)
                                                .collect::<String>();
                                            SessionStorage::set(STATE_OAUTH_KEY, new_oauth_state.clone()).unwrap();
                                            SessionStorage::set(STATE_OAUTH_BASE_URL, data.get("base-url").unwrap()).unwrap();

                                            let mut url = Url::try_from(OAUTH_AUTHORIZE_URL).unwrap();
                                            url.search_params
                                                .insert("client_id".to_string(), OAUTH_CLIENT_ID.to_string());
                                            url.search_params
                                                .insert("response_type".to_string(), "code".to_string());
                                            url.search_params.insert("state".to_string(), new_oauth_state);
                                            url.search_params.insert("redirect_uri".to_string(), callback_url.get_value());
                                            let _ = window().open_with_url_and_target(&format!(
                                                "{}/{}{}",
                                                url.origin,
                                                url.pathname,
                                                url.search_params.to_query_string()
                                            ), "_self");
                                        });
                                    }
                                >
                                Login with SSO
                                </a>
                            </div>
                        </form>
                        </Show>
                    </div>
                </div>
            </div>
        </main>
    }
}

impl Builder<Schemas, ()> {
    pub fn build_login(self) -> Self {
        self.new_schema("login")
            .new_field("login")
            .typ(Type::Input)
            .input_check(
                [Transformer::RemoveSpaces, Transformer::Lowercase],
                [Validator::Required],
            )
            .build()
            .new_field("password")
            .typ(Type::Secret)
            .input_check([], [Validator::Required])
            .build()
            .new_field("base-url")
            .input_check([Transformer::Trim], [Validator::IsUrl])
            .build()
            .new_field("totp-code")
            .input_check([Transformer::Trim], [])
            .build()
            .build()
    }
}
