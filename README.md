# SPF DKIM email verification project.

This project is using existing golang packages since full RFC conformant implementation will take a lot of work.

SPF - RFC 7208
DKIM - RFC 6376

## Run project

1) Clone this repo.
2) Compile executable: ```go build```
3) Execute it with downloaded email message: ```./spf-dkim testEmail.eml```


