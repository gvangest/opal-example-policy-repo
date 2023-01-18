package policies.chro

# CHRO API requires authenticated user
deny["chro_api_authenticated"] {
    regex.match("^/chro/.*",input.uri)
    regex.match("ANONYMOUS",input.principal)
}

# Authorize access to CHRO
allow["chro_api_authorized"] {
    regex.match("^/chro/.+",input.uri)
    input.authorities[i] == "SCOPE_profile"
    can_view_chro
}

can_view_chro {
    some i
    data.teams[i].username == input.principal
}