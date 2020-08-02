# TimingAttack: A Burp Suite Extension

### Context
Burp Suite is used by a huge percentage of security professionals, especially penetration testers. It is often used as an HTTP interception tool. Burp Suite's utility is greatly improved by a variety of plugins, many of which are free to use.

TimingAttack is also an open source plugin to help pentesters for guessing if a username is valid or not by how long the system takes to respond for a fail authentication. And then, comparing that to how long the system takes to respond for a valid one. In other words, if attackers can guess one valid username, then they can guess much more using the same technique.

## What is a Timing Attack?
When a system does not take constant time to return a result for any username inputted, an attacker can use this to inflitrate it. Knowing how long a response takes for one valid and one invalid username, the attacker can check how long other usernames take to get a response, and use that to try to guess which usernames are valid. This Burp Suite Extension was made to allow pentesters to easily verify whether a website is susceptible to this sort of attack.

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
![Clicking "Send to Timing Attack"](Screenshots/Send-to-timing-attack.png)
#### Valid and invalid usernames
In looking at timing attacks, it is often useful to compare the difference in the time to get a response for a valid username against an invalid username. To do that in this extension, simply enter the valid and invalid usernames in the labeled fields. Then, enter the name of the username parameter used in the request in the "enter parameter" field. Finally, because it is often more useful to average how long it took to get a response from several tries, enter how many tries you want to average right below, and submit.
![Right before submitting](Screenshots/Before-submitting.png)
After submitting, you should see the results of the timing attack the right side of the screen. You should also see several buttons pop up, which will allow you to look at the request and the responses.
![Buttons](Screenshots/top-buttons.png)
#### Usernames from file
Sometimes you might want to check how long each username in a list of usernames takes to get a response, to find out which ones are valid and which are not. To do that, simply choose your txt file containing the username list. For the parameter separator, put down what characters separate the usernames in your list (for example, if your list has "user, admin, test" then the characters ", " would be the separator). Finally, once again put down how many request times you would like to average for each username, and click submit. You will now see a list of all the times on the right. Moreover, if you would like to download the resulting list of usernames and result times, simply click the download button, and the file will appear in your computer's downloads. You can also see all the requests sent and all the responses received, in order and labeled with their username, by clicking the buttons that pop up.
![List of responses](Screenshots/response-list.png)
## Setting up the Testing Site
Want to test this extension on our website first? This is how you set up a testing site:
1. Download the website folder;
2. Use Xampp, if you don't have it, follow this video by Dani Krossing: https://www.youtube.com/watch?v=mXdpCRgR-xE;
3. The info about the database is found in website/includes/dbh.inc.php. Basically:
$servername = "localhost";
$dBUsername = "root";
$dBPassword = "abc123";
$dBName = "webserverdb";
4. Open website/index.php on browser.
