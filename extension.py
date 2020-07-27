from burp import IBurpExtender # for the extension
from burp import ITab # for creating an extension tab
from burp import IExtensionHelpers # for helper methods
from burp import IContextMenuFactory # for adding an option to the right click popup menu
from javax.swing import JPanel # for panels
from javax.swing import JTabbedPane # for tabbed pane in popup dialog
from javax.swing import JMenuItem # for adding menu choices to add a new issue
from java.awt import BorderLayout # for panel layouts
from java.awt import Color # for setting a different background on disabled text areas
from java.awt import Font # for adding bold font to text labels in main tab
from java.util import ArrayList # for arraylist
import sys # provides access to some variables used by the interpreter and to functions that interact strongly with the interpreter
import time # for clock time
import threading # for multiple activities within a single process
import os # for splitting the file name and file extension when importing and exporting
from tab import tab # calling the tab.py file

# if something initially goes wrong
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass


# Burp extender main class
class BurpExtender(IBurpExtender, ITab, IExtensionHelpers, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        """ Implement IBurpExtender when the extension is loaded """
        print "Loading timing attack extension\n"

        # required for easier debugging: https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()

        # keep a reference to callbacks object
        self.callbacks = callbacks

        # set our extension name
        self.callbacks.setExtensionName("Timing Attack")
        self.callbacks.registerContextMenuFactory(self)

        # set tab list inside of timing attack tab
        self.tabList = []

        # create GUI
        self.createGUI()

        # add a custom tab to the main Burp Suite window
        callbacks.addSuiteTab(self)

        print "Extension loaded."
        return


    def getTabCaption(self):
        """ Burp Suite uses this method to obtain the caption that should appear on the custom tab when it is displayed """
        return "Timing Attack"


    def getUiComponent(self):
        """ Burp Suite uses this method to obtain the component that should be used as the contents of the custom tab when it is displayed """
        return self.tab


    def createGUI(self):
        """ Create overall UI for extension, with an inner tab """
        # create the panel that border layout lays out a container, arranging and resizing its components to fit
        self.tab = JPanel(BorderLayout())

        # set the extension name
        self.tab.setName("Timing Attack")

        # create a tabbed pane on the top left of the timing attack tab
        self.tabbedPane = JTabbedPane()
        self.tab.add(self.tabbedPane);
        t = tab(self.callbacks)
        self.tabList.append(t)
        self.tabbedPane.addTab("1", self.tabList[0].getFirstTab())


    def createMenuItems(self, invocation):
        """ Create a menu item on other tabs to allow them to send
        requests to Timing Attack """
        self.context = invocation
        menuList = ArrayList()
        self.messageList = invocation.getSelectedMessages()
        menuItem = JMenuItem("Send to Timing Attack", actionPerformed = self.requestSent)
        # JMenuItem("New",actionPerformed = OnClick)
        menuList.add(menuItem)
        return menuList


    def requestSent(self, event):
        """ A request sent from another tab to the Timing Attack (called
        when another tab presses the menu item from createMenuItems) """
        messageList = self.messageList
        # highlight timing attack tab
        self.highlightTab()

        # delete an empty first tab
        if (len(self.tabList) == 1 and self.tabList[0].curRequest == None):
            self.tabbedPane.remove(0)
            self.tabList.pop()

        # add the new tab
        t = tab(self.callbacks)
        self.tabList.append(t)
        tabNum = len(self.tabList) - 1
        self.tabbedPane.addTab(str(tabNum + 1) + "", self.tabList[tabNum].getFirstTab())
        self.tabList[tabNum].getRequest(messageList)
        self.tabbedPane.setSelectedIndex(tabNum)


    def highlightTab(self):
        """ Highlight the Timing Attack tab when a request is sent
        (called by requestSent) """
        parentTabbedPane = self.getUiComponent().getParent()
        if (parentTabbedPane != None):
            for i in range(parentTabbedPane.getTabCount()):
                if parentTabbedPane.getComponentAt(i) == self.getUiComponent():
                    parentTabbedPane.setBackgroundAt(i, Color(16737843));
                    threading.Timer(5, self.unHighlightTab, [i]).start()


    def unHighlightTab(self, componentNum):
        """ Unhighlight Timing Attack tab after 5 seconds """
        parentTabbedPane = self.getUiComponent().getParent()
        parentTabbedPane.setBackgroundAt(componentNum, Color(000000));

# if something after everything goes wrong
try:
    FixBurpExceptions()
except:
    pass
