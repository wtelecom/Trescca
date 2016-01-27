#!/usr/bin/env python

import os
import sys
import pyinotify
from datetime import datetime

# Class with the types of "interting" events

class MyEventParsed(pyinotify.ProcessEvent):

	def __init__(self):
		self.attack_event = {}
		try:
			self.log = open(sys.argv[2], "a+")
			print "Creating and opening file log: " + sys.argv[2]
		except:
			print "File error"

	def process_IN_ACCESS(self, event):
		self.log.write("ACCESS event at " + str(datetime.today())
		+ "\tElement: " + str(event.pathname) + "\n")
		self.attack_event[event.pathname] = "DEFAULT"

	# Change the flag pevious_event = CREATE
	def process_IN_CREATE(self, event):
		self.log.write("CREATE event at " + str(datetime.today())
		+ "\tElement: " + str(event.pathname) + "\n")
		self.attack_event[event.pathname] = "CREATE"

	def process_IN_DELETE(self, event):
		self.log.write("DELETE event at " + str(datetime.today())
		+ "\tElement: " + str(event.pathname) + "\n")
		print "Attack: deletion intent at " + str(datetime.today())
		self.attack_event[event.pathname] = "DEFAULT"

	# Change flag previous event IF previous == CREATE
	def process_IN_OPEN(self, event):
		self.log.write("OPEN event at " + str(datetime.today())
		+ "\tElement: " + str(event.pathname) + "\n")
		if self.attack_event.get(event.pathname) != "CREATE":
			self.attack_event[event.pathname] = "DEFAULT"
			# print "Suspicious event"

	def process_IN_MODIFY(self, event):
		self.log.write("MODIFY event at" + str(datetime.today())
		+ "\tElement: " + str(event.pathname) + "\n")
		if self.attack_event.get(event.pathname) != "CREATE":
			print self.attack_event[event.pathname]
			print "Attack: modification intent at " + str(datetime.today())
		self.attack_event[event.pathname] = "DEFAULT"

	def process_IN_MOVED_FROM(self, event):
		self.log.write("MOVE event at" + str(datetime.today())
		+ "\tElement: " + str(event.pathname) + "\n")
		print "Attack: object moved at " + str(datetime.today())


def main():

	if(len(sys.argv) != 3):
		print "Usage: python trescca_parser.py [dir_to_watch] [file_to_log]"
		sys.exit()
	else:
		print "\nDirectory to watch: " + sys.argv[1]

    # Run pyinotify and establish its parameters 
	wm = pyinotify.WatchManager()
	wm.add_watch(sys.argv[1], pyinotify.ALL_EVENTS, rec=True)

    # Event monitoring
	event = MyEventParsed()

    # Start the notifications of the "attack" events
	notifier = pyinotify.Notifier(wm, event)
	notifier.loop()

if __name__ == '__main__':
    main()