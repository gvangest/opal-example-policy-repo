package ce

# CE API requires authenticated user
deny["ce_api_authenticated"] {
    regex.match("^/ce/.*",input.uri)
    regex.match("ANONYMOUS",input.principal)
}

# Authorize access to CE
allow["ce_api_authorized"] {
    regex.match("^/ce/.+",input.uri)
    input.authorities[i] == "SCOPE_profile"
}