#   Codesonar to IDA Pro (c) 2019 Alexander Pick

#   Changelog:
#   2019/11/13 - converted to IDA plugin
#   2019/11/13 - fixed expansion problem
#

import urllib
import urlparse
import xml.etree.ElementTree as ET
import sys
import idautils, idc, idaapi, ida_kernwin

initialized = False
color = 0xc7c7ff

class SonarHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    # Mainaction if invoked
    def activate(self, ctx):
        a = IDASonar()
        a.importcsdata()
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class IDASonar(idaapi.plugin_t):
    comment = "Codesonar IDA Integration"
    version = "v1.0"
    website = ""
    help = ""
    wanted_name = "IDASonar"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        global initialized

        if initialized == False:
            initialized = True

        action_desc = idaapi.action_desc_t(
            'my:csintegrate',  # The action name. This acts like an ID and must be unique
            'Load XML Data',  # The action text.
            SonarHandler(),  # The action handler.
            '',  # Optional: the action shortcut
            'Load XML Data from a Codesonar Analysis',  # Optional: the action tooltip (available in menus/toolbar)
        )  # Optional: the action icon (shows when in menus/toolbars) use numbers 1-255

        # Register the action
        idaapi.register_action(action_desc)

        idaapi.attach_action_to_menu("Edit/Codesonar/Fetch Results", 'my:csintegrate', idaapi.SETMENU_APP)

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.about()
        pass

    def term(self):
        return

    def about(self):
        print(self.wanted_name + " " + self.version)

    # add function comments and set color if security issue
    def processDetails(self, warningNode, detailsNode, wType):
        #return None, None

        msgFound = 0
        allmsgs = warningNode.find("id").text + ": "

        func = None

        # sys.stdout.write(".")

        try:
            c = detailsNode.find("s/c") #[@preprocessor='1']
            cParts = c.text.split(":")
            
            #sys.stdout.write(c)            

            for msgNode in detailsNode.findall('msg'):

                detail = msgNode.get("detail")
                if ((detail == None) or (detail == 1)):
                    allmsgs += ET.tostring(msgNode, encoding='UTF-8', method='text')
                    msgFound = 1

            if msgFound == 1:
                cea = cParts[1].strip().lstrip("0")
                ea = long(cea, 16)
                print(cea)
                currentcmt = idaapi.get_cmt(ea, 0)
                if currentcmt:
                    allmsgs = currentcmt + "\n" + allmsgs
                idaapi.set_cmt(ea, allmsgs, 0)
                idc.set_color(ea, idc.CIC_ITEM, color)

                if wType == "Security":
                    idc.set_color(ea, idc.CIC_FUNC, 0xcdffff)
                # else:
                # set_color(ea, CIC_FUNC, 0xffffeb)
                
                # catch if possibly no function is defined in IDA db at the offset or something
                try:
                    func = idaapi.get_func(ea).start_ea
                    currentcmt = idc.get_func_cmt(ea, 1)

                    return func, currentcmt
                except Exception as e:
                    print(e)
                    return None, None
                    pass

            return None, None

        except Exception as e:
            print(e)
            pass

    # add function header comment with details
    def addFuncHeader(self, warningNode, func, currentcmt):
        idc.add_bpt(func, 0, idc.BPT_SOFT)
        idc.enable_bpt(func, False)
        headcomment = "Warning! " + warningNode.find("id").text + " Possible " + warningNode.find(
            "class").text + " (Score:" + warningNode.find("score").text + ")"
        if currentcmt:
            headcomment = currentcmt + "\n" + headcomment
        idc.set_func_cmt(func, headcomment, 1)
        return None

    def importcsdata(self):

        url = ida_kernwin.ask_str("http://127.0.0.1:7340/analysis/", 250, "Codesonar Analysis XML URL")

        try:

            if url == False:
                print("IDASonar: Loading aborted!")
                return

            baseurl = parsed_uri = urlparse.urlparse(url)

            root = ET.parse(urllib.urlopen(url)).getroot()

            ida_kernwin.show_wait_box("Processing Codesonar data please wait!")

            for warningNode in root.findall('warning'):
                warningUrl = warningNode.get('url')
                # print(warningUrl)
                # if int(warningNode.find("score").text) < 55:
                #    continue
                procedureNode = warningNode.find("procedure")
                print(procedureNode.text + " " + warningNode.find("class").text)
                host = '{uri.scheme}://{uri.netloc}'.format(uri=baseurl)
                fullWarningUrl = (host + warningUrl)
                WarningDetails = ET.parse(urllib.urlopen(fullWarningUrl)).getroot()

                func = None
                currentcmt = None

                wType = WarningDetails.get("significance")
                print("Significance: " + wType)

                # do for main

                for detailsNode in WarningDetails.findall('listing/procedure/line'):
                    func, currentcmt = self.processDetails(warningNode, detailsNode, wType)

                if func:
                    self.addFuncHeader(warningNode, func, currentcmt)

                # do again for expansions

                func = None

                for detailsNode in WarningDetails.findall('listing/procedure/line/expansion/procedure/line'):
                    func, currentcmt = self.processDetails(warningNode, detailsNode, wType)

                if func:
                    self.addFuncHeader(warningNode, func, currentcmt)

                print("------------------------------------------------------------------")


            print("Done!")
            ida_kernwin.hide_wait_box()
            idaapi.request_refresh(0xFFFFFFFF)

        except Exception as e:
            print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno))
            print(e)
            ida_kernwin.hide_wait_box()
            print("IDASonar: An error occurred while processing the URL!")
            pass


def PLUGIN_ENTRY():
    return IDASonar()
