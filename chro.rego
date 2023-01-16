package chro

# CHRO API requires authenticated user
deny["chro_api_authenticated"] {
    regex.match("^/chro/.*",input.uri)
    regex.match("ANONYMOUS",input.principal)
}

# Authorize access to CHRO
allow["chro_api_authorized"] {
    regex.match("^/chro/.+",input.uri)
    input.authorities[i] == "SCOPE_chro"
}