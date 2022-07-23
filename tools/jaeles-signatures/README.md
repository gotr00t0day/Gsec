<p align="center">
  <img alt="OsmedeusEngine" src="https://raw.githubusercontent.com/osmedeus/assets/main/logo-transparent.png" height="200" />
  <p align="center">
    This project was part of Osmedeus Engine. Check out how it was integrated at <a href="https://docs.osmedeus.org">@OsmedeusEngine</a>
  </p>
</p>

***

<p align="center">
  <h4>
    This repo only contain Default Signatures for <a href="https://github.com/jaeles-project/jaeles">Jaeles</a> project. Pull requests or any ideas are welcome.
  </h4>
  <h4>
  Please read the Official Documentation <a href="https://jaeles-project.github.io/signatures/">here</a> for writing your own signature.
  </h4>
</p>

***

### Installation

```
jaeles config init
```

Or

Try to clone signatures folder to somewhere like this
```
git clone --depth=1 https://github.com/jaeles-project/jaeles-signatures /tmp/jaeles-signatures/
```

then reload them in the DB with this command.

```
jaeles config -a reload --signDir /tmp/jaeles-signatures
```

### Usage

```
Scan Usage example:
  jaeles scan -s <signature> -u <url>
  jaeles scan -c 50 -s <signature> -U <list_urls> -L <level-of-signatures>
  jaeles scan -c 50 -s <signature> -U <list_urls>
  jaeles scan -c 50 -s <signature> -U <list_urls> -p 'dest=xxx.burpcollaborator.net'
  jaeles scan -c 50 -s <signature> -U <list_urls> -f 'noti_slack "{{.vulnInfo}}"'
  jaeles scan -v -c 50 -s <signature> -U list_target.txt -o /tmp/output
  jaeles scan -s <signature> -s <another-selector> -u http://example.com
  jaeles scan -G -s <signature> -s <another-selector> -x <exclude-selector> -u http://example.com
  cat list_target.txt | jaeles scan -c 100 -s <signature>
  jaeles scan -s '/tmp/custom-signature/sensitive/.*' -L 2 --fi

Examples:
  jaeles scan -s 'jira' -s 'ruby' -u target.com
  jaeles scan -c 50 -s 'java' -x 'tomcat' -U list_of_urls.txt
  jaeles scan -G -c 50 -s '/tmp/custom-signature/.*' -U list_of_urls.txt
  jaeles scan -v -s '~/my-signatures/products/wordpress/.*' -u 'https://wp.example.com/blog/' -p 'root=[[.URL]]'
  cat urls.txt | grep 'interesting' | jaeles scan -c 50 -s /tmp/jaeles-signatures/cves/sample.yaml -U list_of_urls.txt --proxy http://127.0.0.1:8080

Config Command examples:
  # Init default signatures
  jaeles config init

  # Update latest signatures
  jaeles config update
  jaeles config update --repo http://github.com/jaeles-project/another-signatures --user admin --pass admin
  jaeles config update --repo git@github.com/jaeles-project/another-signatures -K your_private_key

  # Reload signatures from a standard signatures folder (contain passives + resources)
  jaeles config reload --signDir ~/standard-signatures/

  # Add custom signatures from folder
  jaeles config add --signDir ~/custom-signatures/

  # Clean old stuff
  jaeles config clean

  # More examples
  jaeles config add --signDir /tmp/standard-signatures/
  jaeles config cred --user sample --pass not123456

For full Usage:
  jaeles -hh
```

***

### Structure of the Repo

Jaeles look for signature as a single file so you can structure it as whatever you want. This is just an example.

| Page           | Description                        |
|----------------|------------------------------------|
| **common**     | Implement misconfiguration for some popular apps  |
| **cves**       | Implement some CVE |
| **sensitvie**       | Some common path with sensitive information |
| **probe**      | Used for detect some technology used by the target|
| **passives**      | Used for [passive detection](https://jaeles-project.github.io/signatures/passive/)|
| **fuzz**       | Some common case for fuzz mode (I know a lot of false positive here) |
| **routines**       | Routines example |

## Note for using Fuzz signatures
Fuzz signatures may have many false positive because I can't defined exactly what is vulnerable for everything. So make sure you gotta know what are you doing here.

## Showcases

|  [![asciicast](https://asciinema.org/a/392827.svg)](https://asciinema.org/a/392827) [**Jenkins Gitlab XSS CVE-2020-2096**](https://asciinema.org/a/392827)  |  [![asciicast](https://asciinema.org/a/392822.svg)](https://asciinema.org/a/392822) [**Grafana DoS Probing CVE-2020-13379**](https://asciinema.org/a/392822) |
|:----------:|:-------------:|
| [![asciicast](https://asciinema.org/a/392824.svg)](https://asciinema.org/a/392824) [**SolarWindsOrion LFI CVE-2020-10148**](https://asciinema.org/a/392824) | [![asciicast](https://asciinema.org/a/392821.svg)](https://asciinema.org/a/392821) [**Nginx Vhost XSS**](https://asciinema.org/a/392821) |

<h4 align='center'> More showcase can be found <a href="https://jaeles-project.github.io/showcases/">here</a></h4>

***

## What should I do if Jaeles found a vulnerability?

1. Read the signature file.
2. Seriously, read the signature file.
3. Remember that you were warned twice about reading the signature file.
4. Read the references and detection part to understand why Jaeles said it's vulnerable.
5. Manually verify the vulnerability.


### Financial Contributors

Become a financial contributor and help us sustain our community. [[Contribute](https://opencollective.com/jaeles-project/contribute)]


## Special Thanks

<p align="center">
<img src="https://raw.githubusercontent.com/cvebase/cvebase.com/main/assets/cvebase-logo.png" alt="cvebase" title="cvebase" />
<p align="center">
Explore the latest vulnerabilities at <a href="https://cvebase.com" >cvebase.com</a>
</p>
</p>




## License

`Jaeles` is made with ♥  by [@j3ssiejjj](https://twitter.com/j3ssiejjj) and it is released under the MIT license.

## Donation

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://paypal.me/j3ssiejjj)

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/j3ssie)