package de.trustylynx.models

// These headers only say WHAT is meant (vault token, item), never WHO is asking.
// Who is asking only comes from the login token.

const val VAULT_TOKEN_HEADER = "X-Vault-Token"

// the docs have the itemId in the path, we decided on 2026-10-21 to put it in a header
const val ITEM_ID_HEADER = "X-Item-Id"

const val SERVICE_TOKEN_HEADER = "X-Service-Token"
