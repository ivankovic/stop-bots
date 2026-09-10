/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! Placeholder for the bots screen.

use axum::extract::{Query, State};
use axum::response::Response;
use axum::Router;

use crate::web::layout::Tab;
use crate::web::server::{render, Auth, FlashQuery};
use crate::web::state::AppState;

pub async fn page(
    State(_state): State<AppState>,
    auth: Auth,
    Query(flash): Query<FlashQuery>,
) -> Response {
    render(
        Tab::Bots,
        &auth.csrf,
        flash.into_flash(),
        maud::html! { p { "Not built yet." } },
    )
}

pub fn actions() -> Router<AppState> {
    Router::new()
}
