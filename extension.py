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

#
# Burp extender main class
#
class BurpExtender(IBurpExtender, ITab, IExtensionHelpers, IContextMenuFactory):
    # implement IBurpExtender when the extension is loaded
    def registerExtenderCallbacks(self, callbacks):
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

    # Burp Suite uses this method to obtain the caption that should appear on the custom tab when it is displayed
    def getTabCaption(self):
        return "Timing Attack"

    # Burp Suite uses this method to obtain the component that should be used as the contents of the custom tab when it is displayed
    def getUiComponent(self):
        return self.tab

    # create GUI
    def createGUI(self):
        # create the tab
        self.tab = JPanel(BorderLayout())
        self.tab.setName("Timing Attack")


        # create a tabbed pane on the top left of the timing attack tab (in general, it's going to be numbers)
        # it is necessary to open how many timing attack we want but still in the same timing attack tab
        self.tabbedPane = JTabbedPane()
        self.tab.add(self.tabbedPane);
        t = tab(self.callbacks)
        self.tabList.append(t)
        self.tabbedPane.addTab("1", self.tabList[0].getFirstTab())



    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = ArrayList()
        menuItem = JMenuItem("Send to Timing Attack",
                              actionPerformed=self.requestSent(messageList=invocation.getSelectedMessages()))
        menuList.add(menuItem)
        return menuList

    def requestSent(self, messageList):
        self.highlightTab()
        # If there is an empty first tab, delete it
        if (len(self.tabList) == 1 and self.tabList[0].curRequest == None):
            self.tabbedPane.remove(0)
            self.tabList.pop()

        # Add the new tab
        t = tab(self.callbacks)
        self.tabList.append(t)
        tabNum = len(self.tabList) - 1
        self.tabbedPane.addTab(str(tabNum + 1) + "", self.tabList[tabNum].getFirstTab())
        self.tabList[tabNum].getRequest(messageList)
        self.tabbedPane.setSelectedIndex(tabNum)

    def highlightTab(self):
        parentTabbedPane = self.getUiComponent().getParent()
        if (parentTabbedPane != None):
            for i in range(parentTabbedPane.getTabCount()):
                if parentTabbedPane.getComponentAt(i) == self.getUiComponent():
                    parentTabbedPane.setBackgroundAt(i, Color(16737843));

# if something after everything goes wrong
try:
    FixBurpExceptions()
except:
    pass
