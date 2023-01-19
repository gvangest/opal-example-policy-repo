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
    user := split(input.uri, "/")[2]
    # can view own chro
    user == input.principal
}

can_view_chro {
    user := split(input.uri, "/")[2]
    some i, j
    # team lead can view chro for team member
    lower(data.teams[i].username) == input.principal
    lower(data.teams[i].members[j].username) == user
}

can_view_chro {
    user := split(input.uri, "/")[2]
    some i, j, k, l
    # team lead can view chro for nested team member
    lower(data.teams[i].username) == input.principal
    data.teams[i].members[j].username == data.teams[k].username
    lower(data.teams[k].members[l].username) == user
}