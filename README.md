# TimingAttack: A Burp Suite Extension

### Context
Burp Suite is used by a huge percentage of security professionals, especially penetration testers. It is often used as an HTTP interception tool. Burp Suite's utility is greatly improved by a variety of plugins, many of which are free to use.

TimingAttack is also a plugin open source to help pentesters for guessing if a username is valid or not by how long time the system takes to respond to an fail authentication. And then, comparing that to how long the system takes to respond for a valid login. It means that if attackers can guess one valid username, then they can guess much more using the same technique.  Best part of it, it is totally automated by the attacker.

## What is a Timing Attack?
A timing attack is ...

## Setting up the Extension
#### Setting up a Python Environment on Burp Suite
First of all, you will need to download Jython Standalone Jar (link here: https://www.jython.org/download.html) in order to be able to run python extensions in Burp Suite.
Navigate to the "Extender" tab on Burp Suite, and choose the sub-tab "Options". Under "Python Environment", select your standalone jar file from your file browser in the first selector.
#### Running the Extension
If you have not run a python extension on Burp Suite before, please see "Setting up a python environment on Burp Suite" first.
After doing that, make sure you download both extension.py and tab.py files from this repository, and keep them in the same folder in your file system.
On Burp Suite extension, navigate to the "Extender" tab. Click the "add" button in the top half of the page, and you will see a menu pop up. For the extension type, click "Python"; then select the "extension.py" file for the extension file, and click next. You should see a new tab that says "Timing Attack" among your Burp Suite tabs.

## Using the Extension
To use the extension, you must intercept an HTTP request that sends with it a username. Once you find this request in proxy, right-click to see a menu pop up, and then click "Send to Timing Attack". If you open the Timing Attack tab now, you will see the request in the two boxes on the right side of the screen.
#### Valid and invalid usernames
do this....
#### Usernames from file
do that...

## Setting up the Testing Site
Want to test this extension on our website first? This is how you set up a testing site:
