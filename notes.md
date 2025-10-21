# Incremental RTA

This describes design decisions I make in an API standpoint and also an implementation
standpoint (i.e. This notes contains why I do things the way I did.)

Also I suppose I should make this code as nice as I can so people can actually read it.

# Technical Requirements

- **Previous State Information:**
\
For incremental RTA to work, we would need information which is contained on the previous state of
RTA. For example we would need information from callsites, interfaces, etc. which we previously
analyzed. One challenge to this is that these information is contained within the internal 
`rta` struct.

# API Design
We don't want to modify too much of the existing RTA implementation,
rather the philosophy we are aiming for is about extending existing functionality and also
wrapping over the existing code.

## The Analyze API.
There are several choices of how we should design the API here.

### Modify existing Analyze
This is probably the worst option. Mainly because it would mean IF we were to push this code
upstream, then users' **existing code would not work** with this new CL since they would
have to update it.