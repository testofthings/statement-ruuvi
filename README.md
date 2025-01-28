# Seurity statement: Ruuvi Gateway & Tags

| ⚠  Note | This is an unofficial security statement not endorsed by the manufacturer. |
|---------|--------------------------------|

Security Statement for Ruuvi Gateway & Tags measurement IoT product by [Ruuvi](https://ruuvi.com/).
This statement was originally created for Rauli Kaksonen's [doctoral research](https://urn.fi/URN:NBN:fi:oulu-202406264941).

## Security Statements

Security statements are descriptions of the security posture of IoT devices or products. For more information on security statements and relevant tools, see the [Toolsaf](https://github.com/testofthings/toolsaf) framework.

Once you have set up Toolsaf, you can run the statement with:
```shell
python ruuvi/statement.py
```

## Toolsaf Diagram

Toolsaf creates the following visualization for the statement:

<img src="Ruuvi Gateway & Tags.png" width="40%" alt="Ruuvi Gateway & Tags diagram"></br>

## Known Issues

This security statement has the following known issues:

  - The security statement only covers the Ruuvi Gateway's default services; configuration can enable additional ones.
  - As the product's manufacturer has not been involved, the statement may lack features not observed when the statement was constructed.
