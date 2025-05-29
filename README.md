# PdfScanner
A scanner for finding malicious Javascript embedded in Pdfs  

# Installation
Go is awesome and compiles, so you can just add the .exe to the env path and run it from the command line

# Things to note
*This program is early in production, I have plans to add more features and continue adding ways to detect malicious Javascript in files

*From a security standpoint building from source will be safer. In the case my account ever got hacked, etc. and a malicious .exe was uploaded, but the .go file wasn't altered (since it would be easily auditable); you will still be safe if you build from source. To do this you will need to install golang on your system. It can be downloaded here - https://go.dev/doc/install

Once this is completed run "go build /PathToFile/JavaDetect.go 

This will build an executable that you can then add to path and be on your way :)
