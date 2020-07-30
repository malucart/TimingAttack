"""
Name:           Timing Attack
Date:           7/29/2020
Author:         inbarmada & louisa
Description:    TimingAttack is open source plugin to help pentesters for guessing if a username is valid or not by how long
                the system takes to respond to an fail authentication. And then, comparing that to how long the system takes
                to respond for a valid login. It means that if attackers can guess one valid username, then they can guess
                much more using the same technique. Best part of it, it is totally automated by the attacker.
Copyright (c) 2020, louisa & inbarmada
All rights reserved.
Please see the attached LICENSE file for additional licensing information.
"""

from burp import IBurpExtender # for the extension
from burp import ITab # for creating an extension tab
from burp import IExtensionHelpers # for helper methods
from burp import IContextMenuFactory # for adding an option to the right click popup menu
from burp import IBurpExtenderCallbacks
from javax.swing import JPanel # for panels
from javax.swing import Box # for arranging components either in a row or in a column
from javax.swing import JTextField # for inputting text value in a single line format
from javax.swing import JTextArea # for multi-line text component to display text
from javax.swing import JButton # for buttons
from javax.swing import JSeparator # for implementing divider lines
from javax.swing import JScrollPane # for scroll panes to help with extended text areas
from javax.swing import JLabel # for labels
from javax.swing import JFileChooser # for importing and exporting file chooser
from javax.swing import BoxLayout;
from javax.swing import JDialog
from javax.swing import GroupLayout
from javax import swing
from javax.swing.filechooser import FileNameExtensionFilter # for importing and exporting
from javax.swing.border import EmptyBorder # for an empty/transparent border
from java.awt import BorderLayout # for panel layouts
from java.awt import Color # for setting a different background on disabled text areas
from java.awt import Font # for adding bold font to text labels in main tab
from java.awt import Component # for setting a component
from java.awt import Dimension
from java.util import ArrayList # for arraylist
from java.util import Scanner # for reading file
import sys # provides access to some variables used by the interpreter and to functions that interact strongly with the interpreter
import time # for clock time
import threading # for multiple activities within a single process
import os # for splitting the file name and file extension when importing and exporting
#
# class for the whole UI
#
class tab():

    def __init__(self, callbacks):
        """ Method automatically called when memory is
        allocated for a new object, initiates tab object """
        print("Created a tab")
        self.callbacks = callbacks
        self.curRequest = None

        self.createTabGUI()


    def getFirstTab(self):
        """ Get the JPanel that represents the object's
        Timing Attack tab """
        return self.firstTab


    ###########################
    # SECTION 1: CREATING GUI #
    ###########################

    def createTabGUI(self):

        self.firstTab = JPanel()
        self.titleTop = JLabel("Timing Attack")
        self.titleTop.setFont(Font("Tahoma", 1, 14))
        self.titleTop.setForeground(Color(255,102,51))

        self.infoTop = JLabel("Timing Attack is a open source extention to inform how long the system takes to respond for a valid and an invalid authentication.")
        self.infoTop.setFont(Font("Tahoma", 0, 11))

        self.addTitle = JLabel("Enter a Valid and an Invalid Username")
        self.addTitle.setFont(Font("Tahoma", 1, 13))
        self.addTitle.setForeground(Color(255,102,51))

        self.validUsername = swing.JLabel("Valid Username")
        self.validUsername.setFont(Font("Tahoma", 0, 12))
        self.invalidUsername = swing.JLabel("Invalid Username")
        self.invalidUsername.setFont(Font("Tahoma", 0, 12))
        self.parameter = swing.JLabel("Parameter")
        self.parameter.setFont(Font("Tahoma", 0, 12))
        self.average = swing.JLabel("Quantity to Get Average Time")
        self.average.setFont(Font("Tahoma", 0, 12))

        self.addValid = swing.JTextField("")
        self.addInvalid = swing.JTextField("")
        self.addParameter = swing.JTextField("")
        self.addAverage = swing.JTextField("")

        self.submitButton1 = swing.JButton("Submit", actionPerformed=self.timeTwoUsers)

        self.resultTitle = swing.JLabel("Result")
        self.resultTitle.setFont(Font("Tahoma", 1, 13))
        self.resultTitle.setForeground(Color(255,102,51))
        self.showResults = swing.JTextArea("")
        self.showResults.setEditable(False)

        self.showRequestTopIsOn = False
        self.twoUserResultOutput = ""
        self.twoUserViewReq = swing.JButton("View the Request", actionPerformed=self.showRequestTop)

        self.bar = swing.JSeparator(swing.SwingConstants.HORIZONTAL)

        self.addTitleFile = swing.JLabel("Input Username File")
        self.addTitleFile.setFont(Font("Tahoma", 1, 13))
        self.addTitleFile.setForeground(Color(255,102,51))

        self.inputFileButton = swing.JButton("Choose File...", actionPerformed=self.chooseFile)

        self.resultTitleList = swing.JLabel("Result")
        self.resultTitleList.setFont(Font("Tahoma", 1, 13))
        self.resultTitleList.setForeground(Color(255,102,51))
        self.showResultsList = swing.JTextArea("")
        self.showResultsList.setEditable(False)
        showResultsListScroll = swing.JScrollPane(self.showResultsList)

        self.separatorList = swing.JLabel("Separator")
        self.separatorList.setFont(Font("Tahoma", 0, 12))
        self.parameterList = swing.JLabel("Parameter")
        self.parameterList.setFont(Font("Tahoma", 0, 12))
        self.averageList = swing.JLabel("Quantity to Get Average Time")
        self.averageList.setFont(Font("Tahoma", 0, 12))

        self.addSeparatorList = swing.JTextField("")
        self.addParameterList = swing.JTextField("")
        self.addAverageList = swing.JTextField("")

        self.submitButton2 = swing.JButton("Submit", actionPerformed=self.timeUserList)
        self.downloadResultList = JButton("Download Results", actionPerformed=self.downloadResults)

        self.showListRequestIsOn = False
        self.listResultOutput = ""
        self.listViewReq = swing.JButton("View the Request", actionPerformed=self.showListRequest)


        self.somethingWrong = swing.JLabel("Something Wrong?")
        self.debugOn = False
        self.viewDebug = JButton("View debug output", actionPerformed=self.showDebug)
        self.debugText = swing.JTextArea("")
        self.debugText.setVisible(False)

        layout = swing.GroupLayout(self.firstTab)
        self.firstTab.setLayout(layout)



        layout.setHorizontalGroup(
            layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
            # whole layout
            .addGroup(layout.createSequentialGroup()
                .addGap(15)
                # title + description
                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                    .addComponent(self.titleTop)
                    .addComponent(self.infoTop)
                    # titles
                    .addGroup(layout.createSequentialGroup()
                        # title left
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                            .addComponent(self.addTitle))
                            .addGap(168)
                        # title right
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                            .addComponent(self.resultTitle)))

                    .addGroup(layout.createSequentialGroup()
                        # top left
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                            .addComponent(self.validUsername)
                            .addComponent(self.invalidUsername)
                            .addComponent(self.parameter)
                            .addComponent(self.average)
                            .addComponent(self.addTitleFile)
                            .addComponent(self.inputFileButton)
                            .addComponent(self.separatorList)
                            .addComponent(self.parameterList)
                            .addComponent(self.averageList)
                            .addComponent(self.somethingWrong))
                            .addGap(12)
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                            .addComponent(self.addValid, swing.GroupLayout.PREFERRED_SIZE, 200, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.addInvalid, swing.GroupLayout.PREFERRED_SIZE, 200, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.addParameter, swing.GroupLayout.PREFERRED_SIZE, 200, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.addAverage, swing.GroupLayout.PREFERRED_SIZE, 80, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.submitButton1)
                            .addComponent(self.addSeparatorList, swing.GroupLayout.PREFERRED_SIZE, 200, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.addParameterList, swing.GroupLayout.PREFERRED_SIZE, 200, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.addAverageList, swing.GroupLayout.PREFERRED_SIZE, 80, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.submitButton2)
                            .addComponent(self.viewDebug))
                        .addGap(50)
                        # top right
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                            .addComponent(self.showResults, swing.GroupLayout.PREFERRED_SIZE, 300, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.twoUserViewReq)
                            .addComponent(self.resultTitleList)
                            .addComponent(showResultsListScroll, swing.GroupLayout.PREFERRED_SIZE, 300, swing.GroupLayout.PREFERRED_SIZE)
                            # buttons right
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(self.downloadResultList))
                                .addGap(15)
                                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(self.listViewReq)))
                            .addGap(10)
                            .addComponent(self.debugText, swing.GroupLayout.PREFERRED_SIZE, 300, swing.GroupLayout.PREFERRED_SIZE))))))


        layout.setVerticalGroup(
            layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
            # whole layout
            .addGroup(layout.createSequentialGroup()
                .addGap(15)
                .addComponent(self.titleTop)
                .addGap(10)
                .addComponent(self.infoTop)
                .addGap(10)
                # titles
                .addGroup(layout.createSequentialGroup()
                    # left
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                        .addComponent(self.addTitle)
                        .addGap(25)
                    # right
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                        .addComponent(self.resultTitle))))
                # top half
                .addGroup(layout.createSequentialGroup()
                    # left
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.validUsername)
                                .addGap(5)
                                .addComponent(self.addValid, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(5)
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.invalidUsername)
                                .addGap(5)
                                .addComponent(self.addInvalid, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(5)
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.parameter)
                                .addGap(5)
                                .addComponent(self.addParameter, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(5)
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.average)
                                .addGap(5)
                                .addComponent(self.addAverage, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE)))
                            .addGap(5)
                    # right
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(self.showResults, swing.GroupLayout.PREFERRED_SIZE, 120, swing.GroupLayout.PREFERRED_SIZE))))
                .addGap(5)
                # buttons + titles
                .addGroup(layout.createSequentialGroup()
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(self.submitButton1)
                        .addGap(10)
                        .addComponent(self.twoUserViewReq))
                        .addGap(10)
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(self.addTitleFile)
                        .addGap(25)
                        .addComponent(self.resultTitleList)))
                        .addGap(3)
                # bottom half
                .addGroup(layout.createSequentialGroup()
                    # left
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.inputFileButton))
                                .addGap(10)
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.separatorList)
                                .addGap(5)
                                .addComponent(self.addSeparatorList, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(5)
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.parameterList)
                                .addGap(5)
                                .addComponent(self.addParameterList, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(5)
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.averageList)
                                .addGap(5)
                                .addComponent(self.addAverageList, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE)))
                                .addGap(5)
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(showResultsListScroll, swing.GroupLayout.PREFERRED_SIZE, 122, swing.GroupLayout.PREFERRED_SIZE))))
                .addGap(5)
                # buttons
                .addGroup(layout.createSequentialGroup()
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(self.submitButton2)
                        .addGap(10)
                        .addComponent(self.downloadResultList)
                        .addGap(10)
                        .addComponent(self.listViewReq)))
                .addGap(30)
                .addGroup(layout.createSequentialGroup()
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(self.somethingWrong)
                        .addGap(10)
                        .addComponent(self.debugText)
                        .addGap(10)
                        .addComponent(self.viewDebug)
                        .addGap(10)
                        .addComponent(self.debugText, swing.GroupLayout.PREFERRED_SIZE, 122, swing.GroupLayout.PREFERRED_SIZE)))))


        """ Create GUI for this tabbed pane """
        # create main panel to the whole layout
        """
        self.firstTab = JPanel()
        self.firstTab.layout = BorderLayout()

        # create a big box to organize the layout inside of it
        pagebox = Box.createVerticalBox()

        # create a box for the title of the layout
        toptitle = Box.createHorizontalBox()
        pagebox.add(toptitle)
        title = self.createTopTitle()
        toptitle.add(title)

        # create a box for top-half area and add to the page
        tophalf = Box.createHorizontalBox()
        pagebox.add(tophalf)

        # create top-left and top-right boxes
        topleft = self.createTopLeftBox()
        topright = self.createTopRightBox()
        # add top-left and top-right boxes to top half
        tophalf.add(topleft)
        tophalf.add(topright)

        # draw a horizontal line right after top-half box
        sep = JSeparator()
        pagebox.add(sep)

        # create a box for bottom-half area and add to the page
        bottomhalf = Box.createHorizontalBox()
        pagebox.add(bottomhalf)

        # create bottom-left and bottom-right boxes
        bottomleft = self.createBottomLeftBox()
        bottomright = self.createBottomRightBox()
        # add bottom-left and bottom-right boxes to bottom-half
        bottomhalf.add(bottomleft)
        bottomhalf.add(bottomright)

        # draw a horizontal line after bottom-half box
        sep = JSeparator()
        pagebox.add(sep)


        # create a box for debugging output and add to page
        debugbox = self.createDebugBox()
        pagebox.add(debugbox)


        # timing attack tab adds the big box
        self.firstTab.add(pagebox)

        # the whole tab is returned
        return self.firstTab


    def createTopTitle(self):
        toptitle = self.getBorderVertBox()
        title = JPanel()
        self.addTitle("Timing Attack", title)
        toptitle.add(title)
        toptitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        return toptitle


    def createTopLeftBox(self):
        # Method to create the top left box
        topleft = self.getBorderVertBox()

        # title for the top-left area
        self.addTitle("Enter a Valid and an Invalid Username", topleft)

        # create a box for label and valid username input
        boxHor = Box.createHorizontalBox()

        # create a label for valid username into the box
        self.addLabel("Valid username: ", boxHor)

        # create input for valid username
        self.validUser = JTextField("", 30)

        # the box adds the valid username input
        boxHor.add(self.validUser)

        # top-left box adds this box
        topleft.add(boxHor)

        # create a box for an invalid username input
        boxHor = Box.createHorizontalBox()

        # create a label for an invalid username into the box
        self.addLabel("Invalid username: ", boxHor)

        # create input for invalid username
        self.invalidUser = JTextField("", 30)

        # the box adds the invalid username input
        boxHor.add(self.invalidUser)

        # top-left box adds this box
        topleft.add(boxHor)

        # create a box for the parameter input
        boxHor = Box.createHorizontalBox()

        # create a label for the parameter into the box
        self.addLabel("Enter parameter: ", boxHor)

        # create input for parameter
        self.parameterName = JTextField("", 30)

        # the box adds the parameter input
        boxHor.add(self.parameterName)

        # top-left box adds this box
        topleft.add(boxHor)
        # create new horizontal box for number of tries
        boxHor = Box.createHorizontalBox()

        # create a label for the number of tries into the box
        self.addLabel("How many tries would you like to average: ", boxHor)

        # create input for number of tries
        self.numTries = JTextField("", 30)

        # the box adds the number of tries input
        boxHor.add(self.numTries)

        # top-left box adds this box
        topleft.add(boxHor)

        # "submit" button is created and added into the top-left box
        submit = JButton("submit", actionPerformed=self.timeTwoUsers)
        topleft.add(submit)

        return topleft


    def createTopRightBox(self):
        # Method to create the top right box
        topright = self.getBorderVertBox()

        # title for the top-right area
        self.addTitle("Results", topright)

        # show results in a text area
        self.getResults = JTextArea("", 50, 30)

        # results are not editable
        self.getResults.setEditable(False)

        # top-right adds this text area
        topright.add(self.getResults)

        # "view the request" button is created and added into the top-right box
        self.showRequestTopIsOn = False
        self.twoUserResultOutput = ""
        self.twoUserViewReq = JButton("View the request", actionPerformed=self.showRequestTop)
        topright.add(self.twoUserViewReq)

        return topright


    def createBottomLeftBox(self):
        # Method to create the bottom left box
        bottomleft = self.getBorderVertBox()
        # title for the bottom-left area
        self.addTitle("Input Username File", bottomleft)

        # creates a box to input a list of usernames (txt file)
        boxHor = Box.createHorizontalBox()
        self.addLabel("Input file: ", boxHor)
        self.inputFile = JButton("Choose file...", actionPerformed=self.chooseFile)
        boxHor.add(self.inputFile)
        # bottom-left box adds this box
        bottomleft.add(boxHor)

        # creates a box to input a parameter separator
        boxHor = Box.createHorizontalBox()
        self.addLabel("Enter parameter separator: ", boxHor)
        self.paramSeparator = JTextField("", 30)
        boxHor.add(self.paramSeparator)
        # bottom-left box adds this box
        bottomleft.add(boxHor)

        # creates a box to input a parameter
        boxHor = Box.createHorizontalBox()
        self.addLabel("Enter parameter: ", boxHor)
        self.fileParameterName = JTextField("", 30)
        boxHor.add(self.fileParameterName)
        # bottom-left box adds this box
        bottomleft.add(boxHor)

        boxHor = Box.createHorizontalBox()
        # create a label for the number of tries into the box
        self.addLabel("How many tries would you like to average: ", boxHor)

        # create input for number of tries
        self.listNumTries = JTextField("", 30)

        # the box adds the number of tries input
        boxHor.add(self.listNumTries)

        # top-left box adds this box
        bottomleft.add(boxHor)

        # "submit" button is created and added into the bottom-left box
        submit = JButton("submit", actionPerformed=self.timeUserList)
        self.fileSubmitError = JLabel("")
        bottomleft.add(submit)
        bottomleft.add(self.fileSubmitError)

        return bottomleft


    def createBottomRightBox(self):
        # Method to create the bottom right box
        bottomright = self.getBorderVertBox()

        # title for the bottom-right area
        self.addTitle("Results", bottomright)

        # show results about of each username from txt file
        self.getListResults = JTextArea("", 50, 30)

        # results are not editable
        self.getListResults.setEditable(False)

        # results are scrollable
        getListResultsContainer = JScrollPane(self.getListResults)

        # these results scrollable are added into the bottom-right
        bottomright.add(getListResultsContainer)

        # create a box to store the buttons funcinalities in the bottom-right area
        boxHor = Box.createHorizontalBox()

        # "download results" button to download the results
        downRes = JButton("Download results", actionPerformed=self.downloadResults)

        # box adds this button
        boxHor.add(downRes)

        # "view the request" button
        self.showListRequestIsOn = False
        self.listResultOutput = ""

        # create a button
        self.listViewReq = JButton("View the request", actionPerformed=self.showListRequest)

        # box adds this button
        boxHor.add(self.listViewReq)

        # bottom-right box adds the box which stores the buttons funcinalities
        bottomright.add(boxHor)

        return bottomright


    def createDebugBox(self):
        # Method to create the debug box
        debugbox = self.getBorderVertBox()
        horizontaldebug = Box.createHorizontalBox()

        # create label for this endding section
        self.addLabel("Something went wrong?", horizontaldebug)

        # button to view debug output
        self.debugOn = False
        self.viewDebug = JButton("View debug output", actionPerformed=self.showDebug)
        horizontaldebug.add(self.viewDebug)
        debugbox.add(horizontaldebug)

        horizontaldebug = Box.createHorizontalBox()
        # create a box that shows the debug output
        self.debugText = JTextArea("", 50, 1)
        self.debugText.setVisible(False)
        # box adds this button
        horizontaldebug.add(self.debugText)
        debugbox.add(horizontaldebug)

        return debugbox


    def getBorderVertBox(self):
        # Method that creates box with a border (padding)
        to put other JComponents in
        boxVert = Box.createVerticalBox()
        bord = EmptyBorder(10, 10, 10, 10)
        boxVert.setBorder(bord)
        return boxVert

    def addLabel(self, text, box):
        # Method that creates a label and adds it to a box
        labelArea = JLabel(text)
        box.add(labelArea)
        labelArea.setAlignmentX(Component.LEFT_ALIGNMENT)
        return


    def addTitle(self, text, box):
        # Method that adds titles for boxes
        # Create orange color variable
        orange = Color(16737843)
        # Create font for titles
        titlefont = Font("Tahoma", 1, 14)
        # Create title
        labelArea = JLabel(text)
        labelArea.setForeground(orange)
        labelArea.setFont(titlefont)
        box.add(labelArea)
        return
"""

    def chooseFile(self, event):
        # Method that allows the user to choose a file of usernames
        # try to load the last used directory
        try:
            # load the directory for future imports/exports
            fileChooserDirectory = self._callbacks.loadExtensionSetting("fileChooserDirectory")

        # there is not a last used directory
        except:
            # set the last used directory to blank
            fileChooserDirectory = ""

        self.chooser = swing.JFileChooser(fileChooserDirectory)
        fileextensions = ["txt"]
        filter = FileNameExtensionFilter("TXT FILES", fileextensions)
        self.chooser.setFileFilter(filter)
        returnVal = self.chooser.showOpenDialog(self.chooser)
        if(returnVal == swing.JFileChooser.APPROVE_OPTION):
            self.inputFile.text = self.chooser.getSelectedFile().getName()


    ##################################
    # SECTION 2: SEND TIMING REQUEST #
    ##################################


    def timeTwoUsers(self, event):
        # Method that sends the current request to getTwoUserTimes
        if (self.curRequest == None):
            self.debugOutput("Timing Attack does not have a request")
            return
        # change button to say show request
        self.showRequestTopIsOn = False
        self.twoUserViewReq.setText("View the Request")
        threading.Thread(target=self.getTwoUserTimes).start()
        return


    def getTwoUserTimes(self):
        # Method that prints the time taken to return responses
        # from one valid username and from one invalid username (called
        # by timeTwoUsers)
        self.twoUserViewReq.setVisible(True)
        self.getResults.text = "Valid username: " + self.validUser.text + " Time: "
        self.getResults.text += str(self.getTime(self.parameterName.text, self.validUser.text, self.numTries.text)) + "\n"
        self.getResults.text += "Invalid username: " + self.invalidUser.text + " Time: "
        self.getResults.text += str(self.getTime(self.parameterName.text, self.invalidUser.text, self.numTries.text))


    def timeUserList(self, event):
        #Method that reads the usernames from file and sends
        # them to getUserListTimes
        # if there is no file, so the program is going to return anything
        if (self.curRequest == None):
            self.debugOutput("Timing Attack does not have a request")
            return
        try:
            # stores the file
            file = self.chooser.getSelectedFile()
            self.fileSubmitError.text = ""

            # reads it
            scan = Scanner(file)
            readFile = ""
            while scan.hasNext():
                readFile += scan.nextLine()

            # divides the file to a list of usernames
            self.userList = readFile.split(self.paramSeparator.text)

            # change button to say show request
            self.showListRequestIsOn = False
            self.listViewReq.setText("View the Request")
            # gets the time for each username
            threading.Thread(target=self.getUserListTimes).start()
        # it will handle the error and send a message about it
        except:
           self.fileSubmitError.text = "No File Submitted"
           self.debugOutput("No File Submitted")
        return


    def getUserListTimes(self):
        # Method that prints the time taken to return responses
        # for each username from file (called by timeUserList)
        self.listViewReq.setVisible(True)
        self.getListResults.text = ""
        for i in self.userList:
            self.getListResults.text += "Username: " + i + " Time: "
            self.getListResults.text += str(self.getTime(self.fileParameterName.text, i, self.listNumTries.text)) + "\n"
        return


    def getTime(self, paramName, paramInput, numTriesText):
        # Method that takes in a username and returns time taken to get
        # its response (called by getTwoUserTimes and getUserListTimes)
        numTries = int(numTriesText)
        # keeps a reference to helpers
        helpers = self.callbacks.getHelpers()
        # Get the request
        request = self.curRequest.getRequest()
        # Get request information
        requestInfo = helpers.analyzeRequest(request)

        # loop through parameters
        for i in requestInfo.getParameters():
            # find username parameter and change its value
            if (i.getName() == paramName):
                # it creates the request
                buildParam = helpers.buildParameter(paramName, paramInput, i.getType())
                newRequest = helpers.updateParameter(request, buildParam)

        if 'newRequest' not in locals():
            self.debugOutput("Parameter " + paramName + " cannot be found in request")
        # it builds an http service to send a request to the website
        httpService = self.curRequest.getHttpService()
        httpService = helpers.buildHttpService(httpService.getHost(), httpService.getPort(), False)

        getTime = 0
        for i in range(numTries):
            # starts the time and it sends the changed request with valid parameter
            start = time.clock()
            makeRequest = self.callbacks.makeHttpRequest(httpService, newRequest)
            makeRequest.getResponse()
            getTime += time.clock() - start

        # return the response
        return getTime / numTries


    ###################################
    # SECTION 3: VIEW REQUEST BUTTONS #
    ###################################


    def showRequestTop(self, event):
        # Method that shows the request for top box
        if (not self.showRequestTopIsOn):
            self.twoUserResultOutput = self.getResults.text
        self.showRequest(self.getResults, self.twoUserViewReq, self.twoUserResultOutput, self.showRequestTopIsOn)
        if self.twoUserResultOutput:
            self.showRequestTopIsOn = not self.showRequestTopIsOn


    def showListRequest(self, event):
        # Method that shows the request from a file of usernames
        if (not self.showListRequestIsOn):
            self.listResultOutput = self.getListResults.text
        self.showRequest(self.getListResults, self.listViewReq, self.listResultOutput, self.showListRequestIsOn)
        if self.listResultOutput:
            self.showListRequestIsOn = not self.showListRequestIsOn


    def showRequest(self, box, button, output, bool):
        # Switch from view request to view result and vice versa
        if (bool):
            if not output:
                return
            else:
                box.text = output
                button.setText("View the Request")

        else:
            helpers = self.callbacks.getHelpers()
            output = box.text
            box.text = helpers.bytesToString(self.curRequest.getRequest())
            button.setText("View Results")


    ###############################
    # SECTION 4: DOWNLOAD BUTTONS #
    ###############################


    def downloadResults(self, event):
        # Method that allows user to download file of times for responses
        # for usernames from list
        if (self.getListResults.text == ""):
            return
        file = open(get_download_path() + "/downloadresults.txt", "w")
        file.write(self.getListResults.text)
        file.close()


    def get_download_path():
        # Method to find path of download folder (called by downloadResults)
        # returns the default downloads path for linux or windows
        if os.name == 'nt':
            import winreg
            sub_key = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
            downloads_guid = '{374DE290-123F-4565-9164-39C4925E467B}'
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub_key) as key:
                location = winreg.QueryValueEx(key, downloads_guid)[0]
            return location
        else:
            return os.path.join(os.path.expanduser('~'), 'downloads')


    ###########################
    # SECTION 5: DEBUG BUTTON #
    ###########################


    def debugOutput(self, message):
        # Write a debug message in the debug box
        self.debugText.text = message
        self.debugText.setVisible(True)
        self.viewDebug.setText("Close Debug Output")
        self.debugOn = True


    def showDebug(self, event):
        # Open or close debug box
        if self.debugOn:
            self.debugText.setVisible(False)
            self.viewDebug.setText("View Debug Output")
            self.debugOn = False
            self.debugText.text = ""
        else:
            self.debugText.setVisible(True)
            self.viewDebug.setText("Close Debug Output")
            self.debugOn = True


    ###################################
    # SECTION 6: TAB RECIEVES REQUEST #
    ###################################


    def getRequest(self, messageList):
        # Method that stores the request sent from proxy
        self.curRequest = messageList[0]
        # Make sure show request tabs start out empty
        self.showRequestTopIsOn = False
        self.showListRequestIsOn = False
        self.twoUserResultOutput = self.getResults.text
        self.listResultOutput = self.getListResults.text
        # Show request in both top and bottom windows
        self.showRequest(self.getResults, self.twoUserViewReq, self.twoUserResultOutput, self.showRequestTopIsOn)
        self.showRequest(self.getListResults, self.listViewReq, self.listResultOutput, self.showListRequestIsOn)
        self.showRequestTopIsOn = True
        self.showListRequestIsOn = True
        self.twoUserViewReq.setVisible(False)
        self.listViewReq.setVisible(False)
