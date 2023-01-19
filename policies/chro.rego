package policies.chro

# CHRO API requires authenticated user
deny["chro_api_authenticated"] {
    regex.match("^/chro/.*",input.uri)
    regex.match("ANONYMOUS",input.principal)
}

# Authorize access to CHRO
allow["chro_api_authorized"] {
    regex.match("^/chro/.+",input.uri)
    input.authorities[h] == "SCOPE_profile"
    user := split(input.uri, "/")[2]
    some i, j
    # team lead can view chro for team member
    lower(data.teams[i].username) == input.principal
    lower(data.teams[i].members[j].username) == user
}

can_view_chro[user] {
    # can view own chro
    user == input.principal
}

can_view_chro[user] {
    some i, j
    # team lead can view chro for team member
    lower(data.teams[i].username) == input.principal
    lower(data.teams[i].members[j].username) == user
}