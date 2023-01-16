package opa

import data.public
import data.ce
import data.chro

# Not authorized by default
default authorized = false
default allow = []
default deny = []

allow := public.allow | ce.allow | chro.allow
deny := public.deny | ce.deny | chro.deny

authorized = true {
count(deny) == 0
count(allow) > 0
}