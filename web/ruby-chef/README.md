# Ruby Chef

- **Category:** web
- **Difficulty:** medium(-hard?)
- **Author:** joseph
- **Description:** _Ruby Chef is now available for beta testing! Functionality is currently limited, but additional features can be easily added due to its modular design._
- **Files:**
    - `publish/ruby-chef.zip` (sha256: 495f2f70e386aa9a62f1335b186b396561b528c847e9efc111ca5baea60a0e83)
- **Flag:** `oiccflag{master_chef_in_the_ruby_kitchen!}`

# Notes

- RCE possible, please deploy at least with readonly fs and `restart: "always"` otherwise people may be able to `rm /flag.txt` or `kill -9 7`
