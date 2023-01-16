package public

# Allow access to /public
allow["public"] {
    regex.match("^/public/.*",input.uri)
}