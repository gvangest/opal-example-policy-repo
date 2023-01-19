package opa

deny["chro_api_authenticated"] {
    # CHRO API requires authenticated user
    regex.match("^/chro/.*",input.uri)
    regex.match("ANONYMOUS",input.principal)
}

allow["chro_api_authorized"] {
    regex.match("^/chro/.+",input.uri)
    input.authorities[i] == "SCOPE_profile"
    can_view_chro
}

deny["chro_api_fgs"] {
    regex.match("^/chro/.+",input.uri)
    input.authorities[i] == "SCOPE_profile"
    limited_by_fgs
}

can_view_chro {
    # can view for self
    user := split(input.uri, "/")[2]
    user == input.principal
}

can_view_chro {
    # team lead can view for team member
    user := split(input.uri, "/")[2]
    some i, j
    lower(data.teams[i].username) == input.principal
    lower(data.teams[i].members[j].username) == user
}

can_view_chro {
    # team lead can view for nested team member
    user := split(input.uri, "/")[2]
    some i, j, k, l
    lower(data.teams[i].username) == input.principal
    data.teams[i].members[j].username == data.teams[k].username
    lower(data.teams[k].members[l].username) == user
}

limited_by_fgs {
    # user can't view because of fine-grained-security
    user := split(input.uri, "/")[2]
    some i, j
    lower(data.FineGrainedSecurity[i].username) == input.principal
    lower(data.FineGrainedSecurity[i].members[j].username) == user
}