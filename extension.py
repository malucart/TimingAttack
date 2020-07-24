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
# provides access to some variables used by the interpreter and to functions that interact strongly with the interpreter
import sys
# allow to use the clock time
import time
# allow multiple activities within a single process
import threading
# allow the user types an input
# allow the user download the results, so the program needs to know the path of the download folder to put the file there
import os

from java.util import ArrayList

sys.path.append(".")
from tab import tab


# if something goes wrong
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

# main class to connect to burp suite
class BurpExtender(IBurpExtender, ITab, IExtensionHelpers, IContextMenuFactory):
    # method that shows the extension is loaded
    def registerExtenderCallbacks(self, callbacks):
        print "Loading timing attack extension\n"

        # it is required for easier debugging:
        # https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()

        # it keeps a reference to callbacks object
        self.callbacks = callbacks

        # sets our extension name
        self.callbacks.setExtensionName("Timing Attack")
        self.callbacks.registerContextMenuFactory(self)

        self.tabList = []
        self.createGUI()

        # adds the custom tab to our burp suite's UI
        callbacks.addSuiteTab(self)

        print "Extension loaded."
        return

    # method that implements ITab
    def getTabCaption(self):
        # returns the text that is displayed on the burp suite's new tab
        return "Timing Attack"

    # method that passes the UI to burp suite
    def getUiComponent(self):
        return self.tab

    # method that organizes a better GUI
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

try:
    FixBurpExceptions()
except:
    pass
