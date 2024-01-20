# Ruby Chef

- **Category:** web
- **Difficulty:** medium(-hard?)
- **Author:** joseph
- **Description:** _Ruby Chef is now available for beta testing! Functionality is currently limited, but additional features can be easily added due to its modular design._
- **Files:**
    - `publish/ruby-chef.zip` (sha256: ed576feb42d53bc57c808c3b020de1a00f59c22d8bfa92c536bc30ee73a823fa)
- **Flag:** `oiccflag{master_chef_in_the_ruby_kitchen!}`

# Notes

- RCE possible, please deploy at least with readonly fs and `restart: "always"` otherwise people may be able to `rm /flag.txt` or `kill -9 7`
