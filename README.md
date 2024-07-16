# Windows Deployment Script

This deployment script is designed to be run with a new Windows installation in order to install all the necessary apps and customize certain settings and privacy options.


# <span style="color:red">Read before running!</span>
- Before running this script, please make sure to read through the script and understand what it does.
- You might need to enable running scripts on your pc before running this.
    - You can check this by running `get-executionpolicy` in Powershell
- Also modify apps.json file to include only the apps you want to install.
    - You can export your current apps with `winget export -o apps.json` and then modify the file to include only the apps you want to install.
- You can disable parts of the script by commenting out the lines you don't want to run in main function.
- **I don't take any responsibility for any damage caused by this script. Use at your own risk.**