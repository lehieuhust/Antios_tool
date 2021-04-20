import os
import ast
import sys
import json
import time
import argparse
import logging
import winreg
import random
import log_helper
import system_fingerprint
import hardware_fingerprint
import telemetry_fingerprint
import random_utils
import registry_helper

from PyQt5.QtGui import QTextOption
from PyQt5 import QtCore, QtGui, QtWidgets
from registry_helper import RegistryKeyType, Wow64RegistryEntry
from system_utils import is_x64os, platform_version

logger = log_helper.setup_logger(name="antidetect", level=logging.INFO, log_to_file=False)

hive = "HKEY_LOCAL_MACHINE"
version_path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

hardware_fp = hardware_fingerprint.HardwareFingerprint()
system_fp = system_fingerprint.WinFingerprint()

CONFIG_FILE_DIR='save_file'
JSON_SAVE_FILE ='save_file/data_save.json'

class Ui_Antios(object):
    def setupUi(self, Antios):
        self.save_json_data = {}
        self.load_json_data = {}

        self.device_id_brackets = ""
        self.random_host = ""
        self.random_user = ""
        self.random_hwprofile_guid = ""
        self.random_machine_guid = ""
        self.random_susclient_id = ""
        self.random_susclient_id_valid = []

        self.random_build_guid = ""
        self.random_build_lab = ""
        self.random_build_lab_ex = ""
        self.random_build = ""
        self.random_build_num = ""
        self.random_version = ""

        self.random_edition_id = ""
        self.random_install_date = 0
        self.random_product_id = ""
        self.random_product_name = ""
        self.random_digital_product_id = []
        self.random_digital_product_id4 = []

        self.random_ie_svskb_num= ""
        self.random_ie_product_id = ""
        self.random_ie_digital_product_id = []
        self.random_ie_digital_product_id4 = []
        self.random_ie_installed_date = []

        try:
            os.mkdir(CONFIG_FILE_DIR)
        except FileExistsError:
            pass
        
        if os.path.isfile(JSON_SAVE_FILE):
            print ("Config file exist")
        else:
            print ("Config file not exist")
            json_file = open(JSON_SAVE_FILE, "w")
            self.init_data_file()
            json_file.close()
        
        Antios.setObjectName("Antios")
        Antios.resize(961, 788)
        font = QtGui.QFont()
        font.setPointSize(9)
        Antios.setFont(font)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("os_icon.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        Antios.setWindowIcon(icon)

        self.error_dialog = QtWidgets.QErrorMessage()
        self.error_dialog.setWindowTitle("Error")

        self.Antios_tab = QtWidgets.QTabWidget(Antios)

        self.verticalLayout = QtWidgets.QVBoxLayout(Antios)
        self.verticalLayout.setObjectName("verticalLayout")
        self.verticalLayout.addWidget(self.Antios_tab)

        font = QtGui.QFont()
        font.setPointSize(9)
        self.Antios_tab.setFont(font)
        self.Antios_tab.setObjectName("Antios_tab")

        self.Telemetry_Network_Hardware = QtWidgets.QWidget()
        self.Telemetry_Network_Hardware.setObjectName("Telemetry_Network_Hardware")

        self.System = QtWidgets.QWidget()
        self.System.setObjectName("System")

        self.Antios_tab.addTab(self.Telemetry_Network_Hardware, "")
        self.Antios_tab.addTab(self.System, "")

        self.groupBox_telemetry = QtWidgets.QGroupBox(self.Telemetry_Network_Hardware)
        self.groupBox_telemetry.setGeometry(QtCore.QRect(0, 20, 927, 81))
        self.groupBox_telemetry.setObjectName("groupBox_telemetry")

        self.label_deviceid = QtWidgets.QLabel(self.groupBox_telemetry)
        self.label_deviceid.setGeometry(QtCore.QRect(10, 30, 70, 35))
        self.label_deviceid.setObjectName("label_deviceid")

        self.label_new_deviceid = QtWidgets.QLabel(self.groupBox_telemetry)
        self.label_new_deviceid.setGeometry(QtCore.QRect(370, 30, 74, 35))
        self.label_new_deviceid.setObjectName("label_new_deviceid")

        self.text_deviceid = QtWidgets.QLineEdit(self.groupBox_telemetry)
        self.text_deviceid.setGeometry(QtCore.QRect(110, 30, 250, 35))
        self.text_deviceid.setObjectName("text_deviceid")
        self.text_deviceid.setReadOnly(True)
        self.text_deviceid.setMaxLength(200)
        self.text_deviceid.setCursorPosition(0)
        
        self.text_rddeviceid = QtWidgets.QLineEdit(self.groupBox_telemetry)
        self.text_rddeviceid.setGeometry(QtCore.QRect(450, 30, 250, 35))
        self.text_rddeviceid.setObjectName("text_rddeviceid")
        self.text_rddeviceid.setReadOnly(True)
        self.text_rddeviceid.setMaxLength(200)
        self.text_rddeviceid.setCursorPosition(0)

        self.checkbox_rd_deviceid = QtWidgets.QCheckBox(self.groupBox_telemetry)
        self.checkbox_rd_deviceid.setGeometry(QtCore.QRect(710, 30, 81, 35))
        self.checkbox_rd_deviceid.setObjectName("checkbox_rd_deviceid")
        self.checkbox_rd_deviceid.stateChanged.connect(self.rd_device_id)

        self.btn_random_telemetry_id = QtWidgets.QPushButton(self.groupBox_telemetry)
        self.btn_random_telemetry_id.setGeometry(QtCore.QRect(800, 29, 121, 37))
        self.btn_random_telemetry_id.setObjectName("btn_random_telemetry_id")
        self.btn_random_telemetry_id.clicked.connect(self.randomize_device_id)

        self.groupBox_network = QtWidgets.QGroupBox(self.Telemetry_Network_Hardware)
        self.groupBox_network.setGeometry(QtCore.QRect(0, 180, 927, 131))
        self.groupBox_network.setObjectName("groupBox_network")

        self.label_hostname = QtWidgets.QLabel(self.groupBox_network)
        self.label_hostname.setGeometry(QtCore.QRect(10, 30, 72, 35))
        self.label_hostname.setObjectName("label_hostname")

        self.label_username = QtWidgets.QLabel(self.groupBox_network)
        self.label_username.setGeometry(QtCore.QRect(10, 70, 72, 35))
        self.label_username.setObjectName("label_username")

        self.label_new_hostname = QtWidgets.QLabel(self.groupBox_network)
        self.label_new_hostname.setGeometry(QtCore.QRect(370, 30, 74, 35))
        self.label_new_hostname.setObjectName("label_new_hostname")

        self.label_new_username = QtWidgets.QLabel(self.groupBox_network)
        self.label_new_username.setGeometry(QtCore.QRect(370, 70, 74, 35))
        self.label_new_username.setObjectName("label_new_username")

        self.text_hostname = QtWidgets.QLineEdit(self.groupBox_network)
        self.text_hostname.setGeometry(QtCore.QRect(110, 30, 250, 35))
        self.text_hostname.setObjectName("text_hostname")
        self.text_hostname.setReadOnly(True)
        self.text_hostname.setMaxLength(200)
        self.text_hostname.setCursorPosition(0)
        
        self.text_rdhostname = QtWidgets.QLineEdit(self.groupBox_network)
        self.text_rdhostname.setGeometry(QtCore.QRect(450, 30, 250, 35))
        self.text_rdhostname.setObjectName("text_rdhostname")
        self.text_rdhostname.setReadOnly(True)
        self.text_rdhostname.setMaxLength(200)
        self.text_rdhostname.setCursorPosition(0)

        self.text_username = QtWidgets.QLineEdit(self.groupBox_network)
        self.text_username.setGeometry(QtCore.QRect(110, 70, 250, 35))
        self.text_username.setObjectName("text_username")
        self.text_username.setReadOnly(True)
        self.text_username.setMaxLength(200)
        self.text_username.setCursorPosition(0)
        
        self.text_rdusername = QtWidgets.QLineEdit(self.groupBox_network)
        self.text_rdusername.setGeometry(QtCore.QRect(450, 70, 250, 35))
        self.text_rdusername.setObjectName("text_rdusername")
        self.text_rdusername.setReadOnly(True)
        self.text_rdusername.setMaxLength(200)
        self.text_rdusername.setCursorPosition(0)

        self.checkbox_rd_hostname = QtWidgets.QCheckBox(self.groupBox_network)
        self.checkbox_rd_hostname.setGeometry(QtCore.QRect(710, 30, 91, 35))
        self.checkbox_rd_hostname.setObjectName("checkbox_rd_hostname")
        self.checkbox_rd_hostname.stateChanged.connect(self.rd_hostname)

        self.checkbox_rd_usename = QtWidgets.QCheckBox(self.groupBox_network)
        self.checkbox_rd_usename.setGeometry(QtCore.QRect(710, 70, 81, 35))
        self.checkbox_rd_usename.setObjectName("checkbox_rd_usename")
        self.checkbox_rd_usename.stateChanged.connect(self.rd_username)

        self.btn_random_network_ids = QtWidgets.QPushButton(self.groupBox_network)
        self.btn_random_network_ids.setGeometry(QtCore.QRect(800, 28, 121, 77))
        self.btn_random_network_ids.setObjectName("btn_random_network_ids")
        self.btn_random_network_ids.clicked.connect(self.randomize_network_ids)

        self.groupBox_hardware = QtWidgets.QGroupBox(self.Telemetry_Network_Hardware)
        self.groupBox_hardware.setGeometry(QtCore.QRect(0, 400, 927, 211))
        self.groupBox_hardware.setObjectName("groupBox_hardware")

        self.label_hwprofileg = QtWidgets.QLabel(self.groupBox_hardware)
        self.label_hwprofileg.setGeometry(QtCore.QRect(10, 40, 91, 35))
        self.label_hwprofileg.setObjectName("label_hwprofileg")

        self.label_new_hwprofileg = QtWidgets.QLabel(self.groupBox_hardware)
        self.label_new_hwprofileg.setGeometry(QtCore.QRect(370, 40, 74, 35))
        self.label_new_hwprofileg.setObjectName("label_new_hwprofileg")

        self.label_machineg = QtWidgets.QLabel(self.groupBox_hardware)
        self.label_machineg.setGeometry(QtCore.QRect(10, 80, 91, 35))
        self.label_machineg.setObjectName("label_machineg")

        self.label_new_machineg = QtWidgets.QLabel(self.groupBox_hardware)
        self.label_new_machineg.setGeometry(QtCore.QRect(370, 80, 74, 35))
        self.label_new_machineg.setObjectName("label_new_machineg")

        self.label_susclientid = QtWidgets.QLabel(self.groupBox_hardware)
        self.label_susclientid.setGeometry(QtCore.QRect(10, 120, 91, 35))
        self.label_susclientid.setObjectName("label_susclientid")

        self.label_new_susclientid = QtWidgets.QLabel(self.groupBox_hardware)
        self.label_new_susclientid.setGeometry(QtCore.QRect(370, 120, 74, 35))
        self.label_new_susclientid.setObjectName("label_new_susclientid")

        self.label_susclientid_vali = QtWidgets.QLabel(self.groupBox_hardware)
        self.label_susclientid_vali.setGeometry(QtCore.QRect(10, 160, 81, 41))
        self.label_susclientid_vali.setObjectName("label_susclientid_vali")

        self.label_new_susclientid_valid = QtWidgets.QLabel(self.groupBox_hardware)
        self.label_new_susclientid_valid.setGeometry(QtCore.QRect(370, 160, 74, 35))
        self.label_new_susclientid_valid.setObjectName("label_new_susclientid_valid")

        self.text_hwprofileg = QtWidgets.QLineEdit(self.groupBox_hardware)
        self.text_hwprofileg.setGeometry(QtCore.QRect(110, 40, 250, 35))
        self.text_hwprofileg.setObjectName("text_hwprofileg")
        self.text_hwprofileg.setReadOnly(True)
        self.text_hwprofileg.setMaxLength(200)
        self.text_hwprofileg.setCursorPosition(0)
        
        self.text_rdhwprofileg = QtWidgets.QLineEdit(self.groupBox_hardware)
        self.text_rdhwprofileg.setGeometry(QtCore.QRect(450, 40, 250, 35))
        self.text_rdhwprofileg.setObjectName("text_rdhwprofileg")
        self.text_rdhwprofileg.setReadOnly(True)
        self.text_rdhwprofileg.setMaxLength(200)
        self.text_rdhwprofileg.setCursorPosition(0)

        self.text_machineg = QtWidgets.QLineEdit(self.groupBox_hardware)
        self.text_machineg.setGeometry(QtCore.QRect(110, 80, 250, 35))
        self.text_machineg.setObjectName("text_machineg")
        self.text_machineg.setReadOnly(True)
        self.text_machineg.setMaxLength(200)
        self.text_machineg.setCursorPosition(0)
        
        self.text_rdmachineg = QtWidgets.QLineEdit(self.groupBox_hardware)
        self.text_rdmachineg.setGeometry(QtCore.QRect(450, 80, 250, 35))
        self.text_rdmachineg.setObjectName("text_rdmachineg")
        self.text_rdmachineg.setReadOnly(True)
        self.text_rdmachineg.setMaxLength(200)
        self.text_rdmachineg.setCursorPosition(0)

        self.text_susclientid = QtWidgets.QLineEdit(self.groupBox_hardware)
        self.text_susclientid.setGeometry(QtCore.QRect(110, 120, 250, 35))
        self.text_susclientid.setObjectName("text_susclientid")
        self.text_susclientid.setReadOnly(True)
        self.text_susclientid.setMaxLength(200)
        self.text_susclientid.setCursorPosition(0)
        
        self.text_rdsusclientid = QtWidgets.QLineEdit(self.groupBox_hardware)
        self.text_rdsusclientid.setGeometry(QtCore.QRect(450, 120, 250, 35))
        self.text_rdsusclientid.setObjectName("text_rdsusclientid")
        self.text_rdsusclientid.setReadOnly(True)
        self.text_rdsusclientid.setMaxLength(200)
        self.text_rdsusclientid.setCursorPosition(0)

        self.text_susclientid_valid = QtWidgets.QLineEdit(self.groupBox_hardware)
        self.text_susclientid_valid.setGeometry(QtCore.QRect(110, 160, 250, 35))
        self.text_susclientid_valid.setObjectName("text_susclientid_valid")
        self.text_susclientid_valid.setReadOnly(True)
        self.text_susclientid_valid.setMaxLength(2000)
        self.text_susclientid_valid.setCursorPosition(0)
        
        self.text_rdsusclientid_vali = QtWidgets.QLineEdit(self.groupBox_hardware)
        self.text_rdsusclientid_vali.setGeometry(QtCore.QRect(450, 160, 250, 35))
        self.text_rdsusclientid_vali.setObjectName("text_rdsusclientid_vali")
        self.text_rdsusclientid_vali.setReadOnly(True)
        self.text_rdsusclientid_vali.setMaxLength(2000)
        self.text_rdsusclientid_vali.setCursorPosition(0)

        self.checkbox_rd_hwprofileg = QtWidgets.QCheckBox(self.groupBox_hardware)
        self.checkbox_rd_hwprofileg.setGeometry(QtCore.QRect(710, 40, 81, 35))
        self.checkbox_rd_hwprofileg.setObjectName("checkbox_rd_hwprofileg")
        self.checkbox_rd_hwprofileg.stateChanged.connect(self.rd_hwprofile_guid)

        self.checkbox_rd_machineg = QtWidgets.QCheckBox(self.groupBox_hardware)
        self.checkbox_rd_machineg.setGeometry(QtCore.QRect(710, 80, 81, 35))
        self.checkbox_rd_machineg.setObjectName("checkbox_rd_machineg")
        self.checkbox_rd_machineg.stateChanged.connect(self.rd_machine_guid)

        self.checkbox_rd_susclientid = QtWidgets.QCheckBox(self.groupBox_hardware)
        self.checkbox_rd_susclientid.setGeometry(QtCore.QRect(710, 120, 81, 35))
        self.checkbox_rd_susclientid.setObjectName("checkbox_rd_susclientid")
        self.checkbox_rd_susclientid.stateChanged.connect(self.rd_susclient_id)

        self.checkbox_rd_susclientid_vali = QtWidgets.QCheckBox(self.groupBox_hardware)
        self.checkbox_rd_susclientid_vali.setGeometry(QtCore.QRect(710, 160, 81, 35))
        self.checkbox_rd_susclientid_vali.setObjectName("checkbox_rd_susclientid_vali")
        self.checkbox_rd_susclientid_vali.stateChanged.connect(self.rd_susclient_id_validation)

        self.btn_random_hardware_ids = QtWidgets.QPushButton(self.groupBox_hardware)
        self.btn_random_hardware_ids.setGeometry(QtCore.QRect(800, 38, 121, 157))
        self.btn_random_hardware_ids.setObjectName("btn_random_hardware_ids")
        self.btn_random_hardware_ids.clicked.connect(self.randomize_hardware_ids)

        self.btn_save_tele_net_hw_setting = QtWidgets.QPushButton(self.Telemetry_Network_Hardware)
        self.btn_save_tele_net_hw_setting.setGeometry(QtCore.QRect(410, 640, 141, 65))
        self.btn_save_tele_net_hw_setting.setObjectName("btn_save_tele_net_hw_setting")
        self.btn_save_tele_net_hw_setting.clicked.connect(self.save_tele_net_hw_setting_json)

        self.groupBox_windowid = QtWidgets.QGroupBox(self.System)
        self.groupBox_windowid.setGeometry(QtCore.QRect(0, 10, 927, 721))
        self.groupBox_windowid.setObjectName("groupBox_windowid")

        self.label_buildguid = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_buildguid.setGeometry(QtCore.QRect(10, 30, 91, 35))
        self.label_buildguid.setObjectName("label_buildguid")

        self.label_buildlab = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_buildlab.setGeometry(QtCore.QRect(10, 70, 91, 35))
        self.label_buildlab.setObjectName("label_buildlab")

        self.label_buildlabex = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_buildlabex.setGeometry(QtCore.QRect(10, 110, 91, 35))
        self.label_buildlabex.setObjectName("label_buildlabex")

        self.label_curbuild = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_curbuild.setGeometry(QtCore.QRect(10, 150, 91, 35))
        self.label_curbuild.setObjectName("label_curbuild")
        
        self.label_curbuild_num = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_curbuild_num.setGeometry(QtCore.QRect(10, 190, 91, 41))
        self.label_curbuild_num.setObjectName("label_curbuild_num")

        self.label_cur_version = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_cur_version.setGeometry(QtCore.QRect(10, 230, 81, 35))
        self.label_cur_version.setObjectName("label_cur_version")

        self.label_digi_productid = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_digi_productid.setGeometry(QtCore.QRect(10, 270, 91, 35))
        self.label_digi_productid.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_digi_productid.setObjectName("label_digi_productid")

        self.label_digi_productid4 = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_digi_productid4.setGeometry(QtCore.QRect(10, 310, 91, 35))
        self.label_digi_productid4.setObjectName("label_digi_productid4")

        self.label_editionid = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_editionid.setGeometry(QtCore.QRect(10, 350, 81, 35))
        self.label_editionid.setObjectName("label_editionid")

        self.label_installdate = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_installdate.setGeometry(QtCore.QRect(10, 390, 91, 35))
        self.label_installdate.setObjectName("label_installdate")

        self.label_productid = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_productid.setGeometry(QtCore.QRect(10, 430, 91, 35))
        self.label_productid.setObjectName("label_productid")

        self.label_productname = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_productname.setGeometry(QtCore.QRect(10, 470, 91, 35))
        self.label_productname.setObjectName("label_productname")

        self.label_iesvckb = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_iesvckb.setGeometry(QtCore.QRect(10, 510, 91, 35))
        self.label_iesvckb.setObjectName("label_iesvckb")

        self.label_ieproductid = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_ieproductid.setGeometry(QtCore.QRect(10, 550, 91, 35))
        self.label_ieproductid.setObjectName("label_ieproductid")

        self.label_iedigitalpro = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_iedigitalpro.setGeometry(QtCore.QRect(10, 590, 91, 35))
        self.label_iedigitalpro.setObjectName("label_iedigitalpro")

        self.label_iedigitalpro4 = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_iedigitalpro4.setGeometry(QtCore.QRect(10, 630, 91, 35))
        self.label_iedigitalpro4.setObjectName("label_iedigitalpro4")

        self.label_ieinstalldate = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_ieinstalldate.setGeometry(QtCore.QRect(10, 670, 91, 35))
        self.label_ieinstalldate.setObjectName("label_ieinstalldate")

        self.label_new_build_num = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_build_num.setGeometry(QtCore.QRect(370, 190, 74, 35))
        self.label_new_build_num.setObjectName("label_new_build_num")

        self.label_new_buildlabex = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_buildlabex.setGeometry(QtCore.QRect(370, 110, 74, 35))
        self.label_new_buildlabex.setObjectName("label_new_buildlabex")

        self.label_new_buildlab = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_buildlab.setGeometry(QtCore.QRect(370, 70, 74, 35))
        self.label_new_buildlab.setObjectName("label_new_buildlab")

        self.label_new_buildguid = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_buildguid.setGeometry(QtCore.QRect(370, 30, 74, 35))
        self.label_new_buildguid.setObjectName("label_new_buildguid")

        self.label_new_build = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_build.setGeometry(QtCore.QRect(370, 150, 74, 35))
        self.label_new_build.setObjectName("label_new_build")

        self.label_new_installdate = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_installdate.setGeometry(QtCore.QRect(370, 390, 74, 35))
        self.label_new_installdate.setObjectName("label_new_installdate")
        
        self.label_new_version = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_version.setGeometry(QtCore.QRect(370, 230, 74, 35))
        self.label_new_version.setObjectName("label_new_version")
        
        self.label_new_digi_productid = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_digi_productid.setGeometry(QtCore.QRect(370, 270, 74, 35))
        self.label_new_digi_productid.setObjectName("label_new_digi_productid")

        self.label_new_digi_productid4 = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_digi_productid4.setGeometry(QtCore.QRect(370, 310, 74, 35))
        self.label_new_digi_productid4.setObjectName("label_new_digi_productid4")
        
        self.label_new_editionid = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_editionid.setGeometry(QtCore.QRect(370, 350, 74, 35))
        self.label_new_editionid.setObjectName("label_new_editionid")

        self.label_new_iedigitalpro = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_iedigitalpro.setGeometry(QtCore.QRect(370, 590, 74, 35))
        self.label_new_iedigitalpro.setObjectName("label_new_iedigitalpro")
        
        self.label_new_productid = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_productid.setGeometry(QtCore.QRect(370, 430, 74, 35))
        self.label_new_productid.setObjectName("label_new_productid")
        
        self.label_new_productname = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_productname.setGeometry(QtCore.QRect(370, 470, 74, 35))
        self.label_new_productname.setObjectName("label_new_productname")

        self.label_new_iesvckb = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_iesvckb.setGeometry(QtCore.QRect(370, 510, 74, 35))
        self.label_new_iesvckb.setObjectName("label_new_iesvckb")

        self.label_new_ieproductid = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_ieproductid.setGeometry(QtCore.QRect(370, 550, 74, 35))
        self.label_new_ieproductid.setObjectName("label_new_ieproductid")

        self.label_new_iedigitalpro4 = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_iedigitalpro4.setGeometry(QtCore.QRect(370, 630, 74, 35))
        self.label_new_iedigitalpro4.setObjectName("label_new_iedigitalpro4")

        self.label_new_ieinstalldate = QtWidgets.QLabel(self.groupBox_windowid)
        self.label_new_ieinstalldate.setGeometry(QtCore.QRect(370, 670, 74, 35))
        self.label_new_ieinstalldate.setObjectName("label_new_ieinstalldate")

        self.text_buildguid = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_buildguid.setGeometry(QtCore.QRect(109, 30, 251, 35))
        self.text_buildguid.setObjectName("text_buildguid")
        self.text_buildguid.setReadOnly(True)
        self.text_buildguid.setMaxLength(200)
        self.text_buildguid.setCursorPosition(0)
        
        self.text_rdbuildguid = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rdbuildguid.setGeometry(QtCore.QRect(449, 30, 251, 35))
        self.text_rdbuildguid.setObjectName("text_rdbuildguid")
        self.text_rdbuildguid.setReadOnly(True)
        self.text_rdbuildguid.setMaxLength(200)
        self.text_rdbuildguid.setCursorPosition(0)

        self.text_buildlab = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_buildlab.setGeometry(QtCore.QRect(109, 70, 251, 35))
        self.text_buildlab.setObjectName("text_buildlab")
        self.text_buildlab.setReadOnly(True)
        self.text_buildlab.setMaxLength(200)
        self.text_buildlab.setCursorPosition(0)
        
        self.text_rdbuildlab = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rdbuildlab.setGeometry(QtCore.QRect(449, 70, 251, 35))
        self.text_rdbuildlab.setObjectName("text_rdbuildlab")
        self.text_rdbuildlab.setReadOnly(True)
        self.text_rdbuildlab.setMaxLength(200)
        self.text_rdbuildlab.setCursorPosition(0)

        self.text_buildlabex = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_buildlabex.setGeometry(QtCore.QRect(109, 110, 251, 35))
        self.text_buildlabex.setObjectName("text_buildlabex")
        self.text_buildlabex.setReadOnly(True)
        self.text_buildlabex.setMaxLength(200)
        self.text_buildlabex.setCursorPosition(0)
        
        self.text_rdbuildlabex = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rdbuildlabex.setGeometry(QtCore.QRect(450, 110, 251, 35))
        self.text_rdbuildlabex.setObjectName("text_rdbuildlabex")
        self.text_rdbuildlabex.setReadOnly(True)
        self.text_rdbuildlabex.setMaxLength(200)
        self.text_rdbuildlabex.setCursorPosition(0)

        self.text_curbuild = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_curbuild.setGeometry(QtCore.QRect(109, 150, 251, 35))
        self.text_curbuild.setObjectName("text_curbuild")
        self.text_curbuild.setReadOnly(True)
        self.text_curbuild.setMaxLength(200)
        self.text_curbuild.setCursorPosition(0)
        
        self.text_rdbuild = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rdbuild.setGeometry(QtCore.QRect(450, 150, 251, 35))
        self.text_rdbuild.setObjectName("text_rdbuild")
        self.text_rdbuild.setReadOnly(True)
        self.text_rdbuild.setMaxLength(200)
        self.text_rdbuild.setCursorPosition(0)

        self.text_curbuild_num = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_curbuild_num.setGeometry(QtCore.QRect(109, 190, 251, 35))
        self.text_curbuild_num.setObjectName("text_curbuild_num")
        self.text_curbuild_num.setReadOnly(True)
        self.text_curbuild_num.setMaxLength(200)
        self.text_curbuild_num.setCursorPosition(0)
        
        self.text_rdbuild_num = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rdbuild_num.setGeometry(QtCore.QRect(450, 190, 251, 35))
        self.text_rdbuild_num.setObjectName("text_rdbuild_num")
        self.text_rdbuild_num.setReadOnly(True)
        self.text_rdbuild_num.setMaxLength(200)
        self.text_rdbuild_num.setCursorPosition(0)

        self.text_cur_version = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_cur_version.setGeometry(QtCore.QRect(109, 230, 251, 35))
        self.text_cur_version.setObjectName("text_cur_version")
        self.text_cur_version.setReadOnly(True)
        self.text_cur_version.setMaxLength(200)
        self.text_cur_version.setCursorPosition(0)
        
        self.text_rdversion = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rdversion.setGeometry(QtCore.QRect(450, 230, 251, 35))
        self.text_rdversion.setObjectName("text_rdversion")
        self.text_rdversion.setReadOnly(True)
        self.text_rdversion.setMaxLength(200)
        self.text_rdversion.setCursorPosition(0)

        self.text_digi_productid = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_digi_productid.setGeometry(QtCore.QRect(109, 270, 251, 35))
        self.text_digi_productid.setObjectName("text_digi_productid")
        self.text_digi_productid.setReadOnly(True)
        self.text_digi_productid.setMaxLength(2000)
        self.text_digi_productid.setCursorPosition(0)
        
        self.text_rddigi_productid = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rddigi_productid.setGeometry(QtCore.QRect(450, 270, 251, 35))
        self.text_rddigi_productid.setObjectName("text_rddigi_productid")
        self.text_rddigi_productid.setReadOnly(True)
        self.text_rddigi_productid.setMaxLength(2000)
        self.text_rddigi_productid.setCursorPosition(0)

        self.text_digi_productid4 = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_digi_productid4.setGeometry(QtCore.QRect(109, 310, 251, 35))
        self.text_digi_productid4.setObjectName("text_digi_productid4")
        self.text_digi_productid4.setReadOnly(True)
        self.text_digi_productid4.setMaxLength(2000)
        self.text_digi_productid4.setCursorPosition(0)
        
        self.text_rddigi_productid4 = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rddigi_productid4.setGeometry(QtCore.QRect(450, 310, 251, 35))
        self.text_rddigi_productid4.setObjectName("text_rddigi_productid4")
        self.text_rddigi_productid4.setReadOnly(True)
        self.text_rddigi_productid4.setMaxLength(2000)
        self.text_rddigi_productid4.setCursorPosition(0)

        self.text_editionid = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_editionid.setGeometry(QtCore.QRect(109, 350, 251, 35))
        self.text_editionid.setObjectName("text_editionid")
        self.text_editionid.setReadOnly(True)
        self.text_editionid.setMaxLength(200)
        self.text_editionid.setCursorPosition(0)
        
        self.text_rdeditionid = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rdeditionid.setGeometry(QtCore.QRect(450, 350, 251, 35))
        self.text_rdeditionid.setObjectName("text_rdeditionid")
        self.text_rdeditionid.setReadOnly(True)
        self.text_rdeditionid.setMaxLength(200)
        self.text_rdeditionid.setCursorPosition(0)

        self.text_installdate = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_installdate.setGeometry(QtCore.QRect(109, 390, 251, 35))
        self.text_installdate.setObjectName("text_installdate")
        self.text_installdate.setReadOnly(True)
        self.text_installdate.setMaxLength(200)
        self.text_installdate.setCursorPosition(0)
        
        self.text_rdinstalldate = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rdinstalldate.setGeometry(QtCore.QRect(450, 390, 251, 35))
        self.text_rdinstalldate.setObjectName("text_rdinstalldate")
        self.text_rdinstalldate.setReadOnly(True)
        self.text_rdinstalldate.setMaxLength(200)
        self.text_rdinstalldate.setCursorPosition(0)

        self.text_productid = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_productid.setGeometry(QtCore.QRect(109, 430, 251, 35))
        self.text_productid.setObjectName("text_productid")
        self.text_productid.setReadOnly(True)
        self.text_productid.setMaxLength(200)
        self.text_productid.setCursorPosition(0)
        
        self.text_rdproductid = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rdproductid.setGeometry(QtCore.QRect(450, 430, 251, 35))
        self.text_rdproductid.setObjectName("text_rdproductid")
        self.text_rdproductid.setReadOnly(True)
        self.text_rdproductid.setMaxLength(200)
        self.text_rdproductid.setCursorPosition(0)

        self.text_productname = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_productname.setGeometry(QtCore.QRect(109, 470, 251, 35))
        self.text_productname.setObjectName("text_productname")
        self.text_productname.setReadOnly(True)
        self.text_productname.setMaxLength(200)
        self.text_productname.setCursorPosition(0)
        
        self.text_rdproductname = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rdproductname.setGeometry(QtCore.QRect(450, 470, 251, 35))
        self.text_rdproductname.setObjectName("text_rdproductname")
        self.text_rdproductname.setReadOnly(True)
        self.text_rdproductname.setMaxLength(200)
        self.text_rdproductname.setCursorPosition(0)

        self.text_iesvckb = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_iesvckb.setGeometry(QtCore.QRect(109, 510, 251, 35))
        self.text_iesvckb.setObjectName("text_iesvckb")
        self.text_iesvckb.setReadOnly(True)
        self.text_iesvckb.setMaxLength(200)
        self.text_iesvckb.setCursorPosition(0)
        
        self.text_rdiesvckb = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rdiesvckb.setGeometry(QtCore.QRect(450, 510, 251, 35))
        self.text_rdiesvckb.setObjectName("text_rdiesvckb")
        self.text_rdiesvckb.setReadOnly(True)
        self.text_rdiesvckb.setMaxLength(200)
        self.text_rdiesvckb.setCursorPosition(0)

        self.text_ieproductid = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_ieproductid.setGeometry(QtCore.QRect(109, 550, 251, 35))
        self.text_ieproductid.setObjectName("text_ieproductid")
        self.text_ieproductid.setReadOnly(True)
        self.text_ieproductid.setMaxLength(200)
        self.text_ieproductid.setCursorPosition(0)

        self.text_rdieproductid = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rdieproductid.setGeometry(QtCore.QRect(450, 550, 251, 35))
        self.text_rdieproductid.setObjectName("text_rdieproductid")
        self.text_rdieproductid.setReadOnly(True)
        self.text_rdieproductid.setMaxLength(200)
        self.text_rdieproductid.setCursorPosition(0)

        self.text_iedigitalpro = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_iedigitalpro.setGeometry(QtCore.QRect(109, 590, 251, 35))
        self.text_iedigitalpro.setObjectName("text_iedigitalpro")
        self.text_iedigitalpro.setReadOnly(True)
        self.text_iedigitalpro.setMaxLength(2000)
        self.text_iedigitalpro.setCursorPosition(0)
        
        self.text_rdiedigitalpro = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rdiedigitalpro.setGeometry(QtCore.QRect(450, 590, 251, 35))
        self.text_rdiedigitalpro.setObjectName("text_rdiedigitalpro")
        self.text_rdiedigitalpro.setReadOnly(True)
        self.text_rdiedigitalpro.setMaxLength(2000)
        self.text_rdiedigitalpro.setCursorPosition(0)

        self.text_iedigitalpro4 = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_iedigitalpro4.setGeometry(QtCore.QRect(109, 630, 251, 35))
        self.text_iedigitalpro4.setObjectName("text_iedigitalpro4")
        self.text_iedigitalpro4.setReadOnly(True)
        self.text_iedigitalpro4.setMaxLength(2000)
        self.text_iedigitalpro4.setCursorPosition(0)
        
        self.text_rdiedigitalpro4 = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rdiedigitalpro4.setGeometry(QtCore.QRect(450, 630, 251, 35))
        self.text_rdiedigitalpro4.setObjectName("text_rdiedigitalpro4")
        self.text_rdiedigitalpro4.setReadOnly(True)
        self.text_rdiedigitalpro4.setMaxLength(2000)
        self.text_rdiedigitalpro4.setCursorPosition(0)

        self.text_ieinstalldate = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_ieinstalldate.setGeometry(QtCore.QRect(109, 670, 251, 35))
        self.text_ieinstalldate.setObjectName("text_ieinstalldate")
        self.text_ieinstalldate.setReadOnly(True)
        self.text_ieinstalldate.setMaxLength(200)
        self.text_ieinstalldate.setCursorPosition(0)
        
        self.text_rdieinstalldate = QtWidgets.QLineEdit(self.groupBox_windowid)
        self.text_rdieinstalldate.setGeometry(QtCore.QRect(450, 670, 251, 35))
        self.text_rdieinstalldate.setObjectName("text_rdieinstalldate")
        self.text_rdieinstalldate.setReadOnly(True)
        self.text_rdieinstalldate.setMaxLength(200)
        self.text_rdieinstalldate.setCursorPosition(0)

        self.checkbox_rd_buildguid = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_buildguid.setGeometry(QtCore.QRect(710, 30, 81, 35))
        self.checkbox_rd_buildguid.setObjectName("checkbox_rd_buildguid")
        self.checkbox_rd_buildguid.stateChanged.connect(self.rd_build_guid)

        self.checkbox_rd_buildlab = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_buildlab.setGeometry(QtCore.QRect(710, 70, 81, 35))
        self.checkbox_rd_buildlab.setObjectName("checkbox_rd_buildlab")
        self.checkbox_rd_buildlab.stateChanged.connect(self.rd_build_lab)

        self.checkbox_rd_buildlabex = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_buildlabex.setGeometry(QtCore.QRect(710, 110, 81, 35))
        self.checkbox_rd_buildlabex.setObjectName("checkbox_rd_buildlabex")
        self.checkbox_rd_buildlabex.stateChanged.connect(self.rd_build_lab_ex)

        self.checkbox_rd_build = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_build.setGeometry(QtCore.QRect(710, 150, 81, 35))
        self.checkbox_rd_build.setObjectName("checkbox_rd_build")
        self.checkbox_rd_build.stateChanged.connect(self.rd_build)

        self.checkbox_rd_build_num = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_build_num.setGeometry(QtCore.QRect(710, 190, 81, 35))
        self.checkbox_rd_build_num.setObjectName("checkbox_rd_build_num")
        self.checkbox_rd_build_num.stateChanged.connect(self.rd_build_num)

        self.checkbox_rd_version = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_version.setGeometry(QtCore.QRect(710, 230, 81, 35))
        self.checkbox_rd_version.setObjectName("checkbox_rd_version")
        self.checkbox_rd_version.stateChanged.connect(self.rd_version)

        self.checkbox_rd_digi_productid = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_digi_productid.setGeometry(QtCore.QRect(710, 270, 81, 35))
        self.checkbox_rd_digi_productid.setObjectName("checkbox_rd_digi_productid")
        self.checkbox_rd_digi_productid.stateChanged.connect(self.rd_digital_product_id)

        self.checkbox_rd_digi_productid4 = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_digi_productid4.setGeometry(QtCore.QRect(710, 310, 81, 35))
        self.checkbox_rd_digi_productid4.setObjectName("checkbox_rd_digi_productid4")
        self.checkbox_rd_digi_productid4.stateChanged.connect(self.rd_digital_product_id4)

        self.checkbox_rd_editionid = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_editionid.setGeometry(QtCore.QRect(710, 350, 81, 35))
        self.checkbox_rd_editionid.setObjectName("checkbox_rd_editionid")
        self.checkbox_rd_editionid.stateChanged.connect(self.rd_edition_id)

        self.checkbox_rd_installdate = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_installdate.setGeometry(QtCore.QRect(710, 390, 81, 35))
        self.checkbox_rd_installdate.setObjectName("checkbox_rd_installdate")
        self.checkbox_rd_installdate.stateChanged.connect(self.rd_install_date)

        self.checkbox_rd_productid = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_productid.setGeometry(QtCore.QRect(710, 430, 81, 35))
        self.checkbox_rd_productid.setObjectName("checkbox_rd_productid")
        self.checkbox_rd_productid.stateChanged.connect(self.rd_product_id)

        self.checkbox_rd_productname = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_productname.setGeometry(QtCore.QRect(710, 470, 81, 35))
        self.checkbox_rd_productname.setObjectName("checkbox_rd_productname")
        self.checkbox_rd_productname.stateChanged.connect(self.rd_product_name)

        self.checkbox_rd_iesvckb = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_iesvckb.setGeometry(QtCore.QRect(710, 510, 81, 35))
        self.checkbox_rd_iesvckb.setObjectName("checkbox_rd_iesvckb")
        self.checkbox_rd_iesvckb.stateChanged.connect(self.rd_IE_SvsKB)

        self.checkbox_rd_ieproductid = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_ieproductid.setGeometry(QtCore.QRect(710, 550, 81, 35))
        self.checkbox_rd_ieproductid.setObjectName("checkbox_rd_ieproductid")
        self.checkbox_rd_ieproductid.stateChanged.connect(self.rd_IE_product_id)

        self.checkbox_rd_iedigitalpro = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_iedigitalpro.setGeometry(QtCore.QRect(710, 590, 81, 35))
        self.checkbox_rd_iedigitalpro.setObjectName("checkbox_rd_iedigitalpro")
        self.checkbox_rd_iedigitalpro.stateChanged.connect(self.rd_IE_digital_product_id)

        self.checkbox_rd_iedigitalpro4 = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_iedigitalpro4.setGeometry(QtCore.QRect(710, 630, 81, 35))
        self.checkbox_rd_iedigitalpro4.setObjectName("checkbox_rd_iedigitalpro4")
        self.checkbox_rd_iedigitalpro4.stateChanged.connect(self.rd_IE_digital_product_id4)

        self.checkbox_rd_ieinstalldate = QtWidgets.QCheckBox(self.groupBox_windowid)
        self.checkbox_rd_ieinstalldate.setGeometry(QtCore.QRect(710, 670, 81, 35))
        self.checkbox_rd_ieinstalldate.setObjectName("checkbox_rd_ieinstalldate")
        self.checkbox_rd_ieinstalldate.stateChanged.connect(self.rd_IE_installed_date)

        self.btn_random_window_ids = QtWidgets.QPushButton(self.groupBox_windowid)
        self.btn_random_window_ids.setGeometry(QtCore.QRect(800, 30, 121, 291))
        self.btn_random_window_ids.setObjectName("btn_random_window_ids")
        self.btn_random_window_ids.clicked.connect(self.randomize_system_ids)

        self.btn_save_window_setting = QtWidgets.QPushButton(self.groupBox_windowid)
        self.btn_save_window_setting.setGeometry(QtCore.QRect(800, 414, 121, 291))
        self.btn_save_window_setting.setObjectName("btn_save_all_window_ids")
        self.btn_save_window_setting.clicked.connect(self.save_all_window_ids_json)

        self.retranslateUi(Antios)
        self.Antios_tab.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(Antios)
        # self.load_gui_data()
        self.load_data_file()
        # self.load_data(self.Antios_tab.currentIndex())

    def retranslateUi(self, Antios):
        _translate = QtCore.QCoreApplication.translate
        Antios.setWindowTitle(_translate("Antios", "Antios"))
        self.groupBox_telemetry.setTitle(_translate("Antios", "Telemetry ID"))
        self.checkbox_rd_deviceid.setText(_translate("Antios", "Random"))
        self.label_deviceid.setText(_translate("Antios", "Device ID:"))
        self.label_new_deviceid.setText(_translate("Antios", "New Value:"))
        self.btn_random_telemetry_id.setText(_translate("Antios", "RANDOMIZE "))
        self.groupBox_hardware.setTitle(_translate("Antios", "Hardware IDs"))
        self.label_hwprofileg.setText(_translate("Antios", "HwProfileGuid:"))
        self.label_machineg.setText(_translate("Antios", "MachineGuid:"))
        self.label_susclientid.setText(_translate("Antios", "SusClientID:"))
        self.label_susclientid_vali.setText(_translate("Antios", "SusClientID\n""Validation:"))
        self.btn_random_hardware_ids.setText(_translate("Antios", "RANDOMIZE\n""ALL"))
        self.btn_save_tele_net_hw_setting.setText(_translate("Antios", "SAVE SETTING"))
        self.label_new_hwprofileg.setText(_translate("Antios", "New Value:"))
        self.label_new_machineg.setText(_translate("Antios", "New Value:"))
        self.checkbox_rd_machineg.setText(_translate("Antios", "Random"))
        self.checkbox_rd_hwprofileg.setText(_translate("Antios", "Random"))
        self.checkbox_rd_susclientid.setText(_translate("Antios", "Random"))
        self.label_new_susclientid_valid.setText(_translate("Antios", "New Value:"))
        self.checkbox_rd_susclientid_vali.setText(_translate("Antios", "Random"))
        self.label_new_susclientid.setText(_translate("Antios", "New Value:"))
        self.groupBox_network.setTitle(_translate("Antios", "Network IDs"))
        self.label_hostname.setText(_translate("Antios", "Hostname:"))
        self.label_username.setText(_translate("Antios", "Username:"))
        self.btn_random_network_ids.setText(_translate("Antios", "RANDOMIZE\n""ALL"))
        self.label_new_hostname.setText(_translate("Antios", "New Value:"))
        self.checkbox_rd_hostname.setText(_translate("Antios", "Random"))
        self.label_new_username.setText(_translate("Antios", "New Value:"))
        self.checkbox_rd_usename.setText(_translate("Antios", "Random"))
        self.Antios_tab.setTabText(self.Antios_tab.indexOf(self.Telemetry_Network_Hardware), _translate("Antios", "Telemetry/Network/Hardware"))
        self.groupBox_windowid.setTitle(_translate("Antios", "Window IDs"))
        self.label_buildguid.setText(_translate("Antios", "BuildGUID:"))
        self.label_buildlabex.setText(_translate("Antios", "BuildLabEx:"))
        self.label_buildlab.setText(_translate("Antios", "BuildLab:"))
        self.label_curbuild.setText(_translate("Antios", "CurrentBuild:"))
        self.label_curbuild_num.setText(_translate("Antios", "Current\n""BuildNumber:"))
        self.btn_random_window_ids.setText(_translate("Antios", "RANDOMIZE\n""ALL"))
        self.label_cur_version.setText(_translate("Antios", "Current\n""Version:"))
        self.label_digi_productid.setText(_translate("Antios", "Digital\n""ProductId:"))
        self.label_productid.setText(_translate("Antios", "ProductId:"))
        self.label_editionid.setText(_translate("Antios", "EditionID:"))
        self.label_installdate.setText(_translate("Antios", "InstallDate:"))
        self.label_digi_productid4.setText(_translate("Antios", "Digital\n""ProductId4:"))
        self.label_ieinstalldate.setText(_translate("Antios", "IE Installed\n""Date:"))
        self.label_ieproductid.setText(_translate("Antios", "IE ProductId:"))
        self.label_iesvckb.setText(_translate("Antios", "IE SvcKB\n""Number:"))
        self.label_iedigitalpro.setText(_translate("Antios", "IE Digital\n""ProductId:"))
        self.label_productname.setText(_translate("Antios", "ProductName:"))
        self.label_iedigitalpro4.setText(_translate("Antios", "IE Digital\n""ProductId4:"))
        self.checkbox_rd_build_num.setText(_translate("Antios", "Random"))
        self.checkbox_rd_buildguid.setText(_translate("Antios", "Random"))
        self.label_new_build_num.setText(_translate("Antios", "New Value:"))
        self.checkbox_rd_buildlab.setText(_translate("Antios", "Random"))
        self.label_new_buildlabex.setText(_translate("Antios", "New Value:"))
        self.label_new_buildlab.setText(_translate("Antios", "New Value:"))
        self.checkbox_rd_build.setText(_translate("Antios", "Random"))
        self.checkbox_rd_buildlabex.setText(_translate("Antios", "Random"))
        self.label_new_buildguid.setText(_translate("Antios", "New Value:"))
        self.label_new_build.setText(_translate("Antios", "New Value:"))
        self.checkbox_rd_digi_productid.setText(_translate("Antios", "Random"))
        self.label_new_installdate.setText(_translate("Antios", "New Value:"))
        self.label_new_version.setText(_translate("Antios", "New Value:"))
        self.label_new_digi_productid.setText(_translate("Antios", "New Value:"))
        self.checkbox_rd_digi_productid4.setText(_translate("Antios", "Random"))
        self.checkbox_rd_version.setText(_translate("Antios", "Random"))
        self.checkbox_rd_editionid.setText(_translate("Antios", "Random"))
        self.label_new_digi_productid4.setText(_translate("Antios", "New Value:"))
        self.label_new_editionid.setText(_translate("Antios", "New Value:"))
        self.checkbox_rd_installdate.setText(_translate("Antios", "Random"))
        self.checkbox_rd_productname.setText(_translate("Antios", "Random"))
        self.label_new_iedigitalpro.setText(_translate("Antios", "New Value:"))
        self.label_new_productid.setText(_translate("Antios", "New Value:"))
        self.label_new_productname.setText(_translate("Antios", "New Value:"))
        self.checkbox_rd_iesvckb.setText(_translate("Antios", "Random"))
        self.checkbox_rd_productid.setText(_translate("Antios", "Random"))
        self.checkbox_rd_ieproductid.setText(_translate("Antios", "Random"))
        self.label_new_iesvckb.setText(_translate("Antios", "New Value:"))
        self.label_new_ieproductid.setText(_translate("Antios", "New Value:"))
        self.checkbox_rd_iedigitalpro.setText(_translate("Antios", "Random"))
        self.checkbox_rd_iedigitalpro4.setText(_translate("Antios", "Random"))
        self.label_new_iedigitalpro4.setText(_translate("Antios", "New Value:"))
        self.label_new_ieinstalldate.setText(_translate("Antios", "New Value:"))
        self.checkbox_rd_ieinstalldate.setText(_translate("Antios", "Random"))
        self.btn_save_window_setting.setText(_translate("Antios", "SAVE SETTING"))
        self.Antios_tab.setTabText(self.Antios_tab.indexOf(self.System), _translate("Antios", "System"))
    
    """
    Load data to Gui
    """
    def load_gui_data(self):
        self.current_device_id = registry_helper.read_value(key_hive=hive,
                                                        key_path="SOFTWARE\\Microsoft\\SQMClient",
                                                        value_name="MachineId")
        if self.current_device_id[1] == winreg.REG_SZ:
            self.text_deviceid.setText(self.current_device_id[0])
            self.text_deviceid.setCursorPosition(0)
        else:
            self.text_deviceid.setText("NULL")
            self.text_deviceid.setCursorPosition(0)
            print("Unexpected type of HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SQMClient Value:MachineId Type:%d" % self.current_device_id[1])

        # Current Hostname
        self.current_host = registry_helper.read_value(key_hive=hive,
                                                       key_path="SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
                                                       value_name="Hostname")
        # Current Username
        self.current_user = registry_helper.read_value(key_hive=hive,
                                                       key_path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                                       value_name="RegisteredOwner")
        
        # Current Hardware profile GUID
        self.cur_hwprofile_guid = registry_helper.read_value(key_hive=hive,
                                                             key_path="SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
                                                             value_name="HwProfileGuid")
        # Current Machine GUID
        self.cur_machine_guid = registry_helper.read_value(key_hive=hive,
                                                           key_path="SOFTWARE\\Microsoft\\Cryptography",
                                                           value_name="MachineGuid")

        # Current Windows Update GUID
        self.cur_susclient_id = registry_helper.read_value(key_hive=hive,
                                                           key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
                                                           value_name="SusClientId")
        
        self.cur_susclient_id_valid = registry_helper.read_value(key_hive=hive,
                                                                 key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
                                                                 value_name="SusClientIDValidation")
        
        self.text_hostname.setText(self.current_host[0])
        self.text_hostname.setCursorPosition(0)

        self.text_username.setText(self.current_user[0])
        self.text_username.setCursorPosition(0)

        self.text_hwprofileg.setText(self.cur_hwprofile_guid[0])
        self.text_hwprofileg.setCursorPosition(0)

        self.text_machineg.setText(self.cur_machine_guid[0])
        self.text_machineg.setCursorPosition(0)

        self.text_susclientid.setText(self.cur_susclient_id[0])
        self.text_susclientid.setCursorPosition(0)

        self.text_susclientid_valid.setText(str(self.cur_susclient_id_valid[0]))
        self.text_susclientid_valid.setCursorPosition(0)

        # Window IDs
        self.cur_buildguid = registry_helper.read_value(key_hive=hive,
                                                        key_path=version_path,
                                                        value_name="BuildGUID")
        
        self.cur_buildlab = registry_helper.read_value(key_hive=hive,
                                                       key_path=version_path,
                                                       value_name="BuildLab")
        
        self.cur_buildlabex = registry_helper.read_value(key_hive=hive,
                                                         key_path=version_path,
                                                         value_name="BuildLabEx")
        
        self.cur_build = registry_helper.read_value(key_hive=hive,
                                                    key_path=version_path,
                                                    value_name="CurrentBuild")
        
        self.cur_build_num = registry_helper.read_value(key_hive=hive,
                                                        key_path=version_path,
                                                        value_name="CurrentBuildNumber")
        
        self.cur_version = registry_helper.read_value(key_hive=hive,
                                                      key_path=version_path,
                                                      value_name="CurrentVersion")
        
        self.cur_digital_product_id = registry_helper.read_value(key_hive=hive,
                                                                 key_path=version_path,
                                                                 value_name="DigitalProductId")
        
        self.cur_digital_product_id4 = registry_helper.read_value(key_hive=hive,
                                                                  key_path=version_path,
                                                                  value_name="DigitalProductId4")
        
        self.cur_edition_id = registry_helper.read_value(key_hive=hive,
                                                         key_path=version_path,
                                                         value_name="EditionID")
        
        self.cur_install_date = registry_helper.read_value(key_hive=hive,
                                                           key_path=version_path,
                                                           value_name="InstallDate")
        
        self.cur_product_id = registry_helper.read_value(key_hive=hive,
                                                         key_path=version_path,
                                                         value_name="ProductId")
        
        self.cur_product_name = registry_helper.read_value(key_hive=hive,
                                                           key_path=version_path,
                                                           value_name="ProductName")
        
        self.cur_IE_SvcKB_Num = registry_helper.read_value(key_hive=hive,
                                                           key_path="SOFTWARE\\Microsoft\\Internet Explorer",
                                                           value_name="svcKBNumber")
        
        self.cur_IE_Product_ID = registry_helper.read_value(key_hive=hive,
                                                            key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration",
                                                            value_name="ProductId")
        
        self.cur_IE_Digi_Product_ID = registry_helper.read_value(key_hive=hive,
                                                                 key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration",
                                                                 value_name="DigitalProductId")
        
        self.cur_IE_Digi_Product_ID4 = registry_helper.read_value(key_hive=hive,
                                                                  key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration",
                                                                  value_name="DigitalProductId4")
        
        self.cur_IE_Install_Date = registry_helper.read_value(key_hive=hive,
                                                              key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Migration",
                                                              value_name="IE Installed Date")
        
        self.text_buildguid.setText(self.cur_buildguid[0])
        self.text_buildguid.setCursorPosition(0)

        self.text_buildlab.setText(self.cur_buildlab[0])
        self.text_buildlab.setCursorPosition(0)

        self.text_buildlabex.setText(self.cur_buildlabex[0])
        self.text_buildlabex.setCursorPosition(0)

        self.text_curbuild.setText(self.cur_build[0])
        self.text_curbuild.setCursorPosition(0)

        self.text_curbuild_num.setText(self.cur_build_num[0])
        self.text_curbuild_num.setCursorPosition(0)

        self.text_cur_version.setText(self.cur_version[0])
        self.text_cur_version.setCursorPosition(0)

        self.text_digi_productid.setText(str(self.cur_digital_product_id[0]))
        self.text_digi_productid.setCursorPosition(0)

        self.text_digi_productid4.setText(str(self.cur_digital_product_id4[0]))
        self.text_digi_productid4.setCursorPosition(0)

        self.text_editionid.setText(self.cur_edition_id[0])
        self.text_editionid.setCursorPosition(0)

        self.text_installdate.setText(str(self.cur_install_date[0]))
        self.text_installdate.setCursorPosition(0)

        self.text_productid.setText(self.cur_product_id[0])
        self.text_productid.setCursorPosition(0)

        self.text_productname.setText(self.cur_product_name[0])
        self.text_productname.setCursorPosition(0)

        self.text_iesvckb.setText(self.cur_IE_SvcKB_Num[0])
        self.text_iesvckb.setCursorPosition(0)

        self.text_ieproductid.setText(self.cur_IE_Product_ID[0])
        self.text_ieproductid.setCursorPosition(0)

        self.text_iedigitalpro.setText(str(self.cur_IE_Digi_Product_ID[0]))
        self.text_iedigitalpro.setCursorPosition(0)

        self.text_iedigitalpro4.setText(str(self.cur_IE_Digi_Product_ID4[0]))
        self.text_iedigitalpro4.setCursorPosition(0)

        self.text_ieinstalldate.setText(str(self.cur_IE_Install_Date[0]))
        self.text_ieinstalldate.setCursorPosition(0)
    
    """
    Initialize data to json file
    """
    def init_data_file(self):
        self.save_json_data = {
            "Device id": '',
            'Hostname': '',
            'Username': '',
            'hwprofile guid': '',
            'machine guid': '',
            'susclient id': '',
            'susclient id validation': '',
            'Build guid': '',
            'Build lab': '',
            'Build labex': '',
            'Current build': '',
            'Current build number': '',
            'Current version': '',
            'Digital ProductId': '',
            'Digital ProductId4': '',
            'Edition Id': '',
            'Install Date': '',
            'Product Id': '',
            'Product Name': '',
            'IE SvsKB Number': '',
            'IE ProductID': '',
            'IE Digital ProductID': '',
            'IE Digital ProductID4': '',
            'IE Installed Date': ''
        }
        self.save_data_file(self.save_json_data)
    
    """
    Save data to json file
    """
    def save_data_file(self, save_data_list):
        with open(JSON_SAVE_FILE, 'w') as outfile:
            json.dump(save_data_list, outfile, indent = 4)
    
    """
    Load data from json file
    """
    def load_data_file(self):
        with open(JSON_SAVE_FILE, 'r') as json_file:
            self.load_json_data = json.load(json_file)
        
        if self.load_json_data['Device id'] == '':
            print ("Device ID is not setup")
        else:
            print("load_json_data['Device id']: ", self.load_json_data['Device id'])
            self.device_id_brackets = self.load_json_data['Device id']
            ret = registry_helper.write_value(key_hive=hive,
                                    key_path="SOFTWARE\\Microsoft\\SQMClient",
                                    value_name="MachineId",
                                    value_type=winreg.REG_SZ,
                                    key_value=self.device_id_brackets)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['Hostname'] == '':
            print ("Hostname is not setup")
        else:
            print("load_json_data['Hostname']: ", self.load_json_data['Hostname'])
            self.random_host = self.load_json_data['Hostname']
            logger.debug("Tcpip\\Parameters NV Hostname={0}".format(self.random_host))
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path="SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
                                        value_name="NV Hostname",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_host)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return

            logger.debug("Tcpip\\Parameters Hostname={0}".format(self.random_host))
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path="SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
                                        value_name="Hostname",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_host)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return

            logger.debug("Tcpip\\Parameters ComputerName={0}".format(self.random_host))
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path="SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
                                        value_name="ComputerName",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_host)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return

            logger.debug("ComputerName\\ActiveComputerName ComputerName={0}".format(self.random_host))
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path="SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",
                                        value_name="ComputerName",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_host)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['Username'] == '':
            print ("Username is not setup")
        else:
            print("load_json_data['Username']: ", self.load_json_data['Username'])
            self.random_user = self.load_json_data['Username']
            logger.debug("Windows NT\\CurrentVersion RegisteredOwner={0}".format(self.random_user))
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                        value_name="RegisteredOwner",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_user,
                                        access_type=Wow64RegistryEntry.KEY_WOW32_64)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['hwprofile guid'] == '':
            print ("hwprofile guid is not setup")
        else:
            print("load_json_data['hwprofile guid']: ", self.load_json_data['hwprofile guid'])
            self.random_hwprofile_guid = self.load_json_data['hwprofile guid']
            # Hardware profile GUID
            logger.debug("Hardware Profiles\\0001 HwProfileGuid")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path="SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
                                        value_name="HwProfileGuid",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_hwprofile_guid)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['machine guid'] == '':
            print ("machine guid is not setup")
        else:
            print("load_json_data['machine guid']: ", self.load_json_data['machine guid'])
            self.random_machine_guid = self.load_json_data['machine guid']
            # Machine GUID
            logger.debug("Microsoft\\Cryptography MachineGuid")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path="SOFTWARE\\Microsoft\\Cryptography",
                                        value_name="MachineGuid",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_machine_guid)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['susclient id'] == '':
            print ("susclient id is not setup")
        else:
            print("load_json_data['susclient id']: ", self.load_json_data['susclient id'])
            self.random_susclient_id = self.load_json_data['susclient id']
            # Windows Update GUID
            logger.debug("CurrentVersion\\WindowsUpdate SusClientId")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
                                        value_name="SusClientId",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_susclient_id)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['susclient id validation'] == '':
            print ("susclient id validation is not setup")
        else:
            print("load_json_data['susclient id validation']: ", self.load_json_data['susclient id validation'])
            self.random_susclient_id_valid = ast.literal_eval(self.load_json_data['susclient id validation'])
            logger.debug("CurrentVersion\\WindowsUpdate SusClientIDValidation")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
                                        value_name="SusClientIDValidation",
                                        value_type=RegistryKeyType.REG_BINARY,
                                        key_value=random_utils.bytes_list_to_array(self.random_susclient_id_valid))
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['Build guid'] == '':
            print ("Build guid is not setup")
        else:
            print("load_json_data['Build guid']: ", self.load_json_data['Build guid'])
            self.random_build_guid = self.load_json_data['Build guid']
            logger.debug("Windows NT\\CurrentVersion BuildGUID")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path=version_path,
                                        value_name="BuildGUID",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_build_guid,
                                        access_type=Wow64RegistryEntry.KEY_WOW32_64)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['Build lab'] == '':
            print ("Build lab is not setup")
        else:
            print("load_json_data['Build lab']: ", self.load_json_data['Build lab'])
            self.random_build_lab = self.load_json_data['Build lab']
            logger.debug("Windows NT\\CurrentVersion BuildLab")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path=version_path,
                                        value_name="BuildLab",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_build_lab,
                                        access_type=Wow64RegistryEntry.KEY_WOW32_64)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['Build labex'] == '':
            print ("Build labex is not setup")
        else:
            print("load_json_data['Build labex']: ", self.load_json_data['Build labex'])
            self.random_build_lab_ex = self.load_json_data['Build labex']
            logger.debug("Windows NT\\CurrentVersion BuildLabEx")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path=version_path,
                                        value_name="BuildLabEx",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_build_lab_ex,
                                        access_type=Wow64RegistryEntry.KEY_WOW32_64)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['Current build'] == '':
            print ("Current build is not setup")
        else:
            print("load_json_data['Current build']: ", self.load_json_data['Current build'])
            self.random_build = self.load_json_data['Current build']
            logger.debug("Windows NT\\CurrentVersion CurrentBuild")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path=version_path,
                                        value_name="CurrentBuild",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_build,
                                        access_type=Wow64RegistryEntry.KEY_WOW32_64)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['Current build number'] == '':
            print ("Current build number is not setup")
        else:
            print("load_json_data['Current build number']: ", self.load_json_data['Current build number'])
            self.random_build_num = self.load_json_data['Current build number']
            logger.debug("Windows NT\\CurrentVersion CurrentBuildNumber")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path=version_path,
                                        value_name="CurrentBuildNumber",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_build_num,
                                        access_type=Wow64RegistryEntry.KEY_WOW32_64)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['Current version'] == '':
            print ("Current version is not setup")
        else:
            print("load_json_data['Current version']: ", self.load_json_data['Current version'])
            self.random_version = self.load_json_data['Current version']
            logger.debug("Windows NT\\CurrentVersion CurrentVersion")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path=version_path,
                                        value_name="CurrentVersion",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_version,
                                        access_type=Wow64RegistryEntry.KEY_WOW32_64)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['Digital ProductId'] == '':
            print ("Digital ProductId is not setup")
        else:
            print("load_json_data['Digital ProductId']: ", self.load_json_data['Digital ProductId'])
            self.random_digital_product_id = ast.literal_eval(self.load_json_data['Digital ProductId'])
            logger.debug("Windows NT\\CurrentVersion DigitalProductId")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path=version_path,
                                        value_name="DigitalProductId",
                                        value_type=RegistryKeyType.REG_BINARY,
                                        key_value=random_utils.bytes_list_to_array(self.random_digital_product_id))
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['Digital ProductId4'] == '':
            print ("Digital ProductId4 is not setup")
        else:
            print("load_json_data['Digital ProductId4']: ", self.load_json_data['Digital ProductId4'])
            self.random_digital_product_id4 = ast.literal_eval(self.load_json_data['Digital ProductId4'])
            logger.debug("Windows NT\\CurrentVersion DigitalProductId4")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path=version_path,
                                        value_name="DigitalProductId4",
                                        value_type=RegistryKeyType.REG_BINARY,
                                        key_value=random_utils.bytes_list_to_array(self.random_digital_product_id4))
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['Edition Id'] == '':
            print ("Edition Id is not setup")
        else:
            print("load_json_data['Edition Id']: ", self.load_json_data['Edition Id'])
            self.random_edition_id = self.load_json_data['Edition Id']
            logger.debug("Windows NT\\CurrentVersion EditionID")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path=version_path,
                                        value_name="EditionID",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_edition_id,
                                        access_type=Wow64RegistryEntry.KEY_WOW32_64)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['Install Date'] == '':
            print ("Install Date is not setup")
        else:
            print("load_json_data['Install Date']: ", self.load_json_data['Install Date'])
            self.random_install_date = self.load_json_data['Install Date']
            logger.debug("Windows NT\\CurrentVersion InstallDate")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path=version_path,
                                        value_name="InstallDate",
                                        value_type=RegistryKeyType.REG_DWORD,
                                        key_value=int(self.random_install_date))
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['Product Id'] == '':
            print ("Product Id is not setup")
        else:
            print("load_json_data['Product Id']: ", self.load_json_data['Product Id'])
            self.random_product_id = self.load_json_data['Product Id']
            logger.debug("Windows NT\\CurrentVersion ProductId")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path=version_path,
                                        value_name="ProductId",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_product_id,
                                        access_type=Wow64RegistryEntry.KEY_WOW32_64)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['Product Name'] == '':
            print ("Product Name is not setup")
        else:
            print("load_json_data['Product Name']: ", self.load_json_data['Product Name'])
            self.random_product_name = self.load_json_data['Product Name']
            logger.debug("Windows NT\\CurrentVersion ProductName")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path=version_path,
                                        value_name="ProductName",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_product_name,
                                        access_type=Wow64RegistryEntry.KEY_WOW32_64)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['IE SvsKB Number'] == '':
            print ("IE SvsKB Number is not setup")
        else:
            print("load_json_data['IE SvsKB Number']: ", self.load_json_data['IE SvsKB Number'])
            
            self.random_ie_svskb_num = self.load_json_data['IE SvsKB Number']
            logger.debug("Microsoft\\Internet Explorer svcKBNumber")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path="SOFTWARE\\Microsoft\\Internet Explorer",
                                        value_name="svcKBNumber",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_ie_svskb_num,
                                        access_type=Wow64RegistryEntry.KEY_WOW32_64)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['IE ProductID'] == '':
            print ("IE ProductID is not setup")
        else:
            print("load_json_data['IE ProductID']: ", self.load_json_data['IE ProductID'])
            self.random_ie_product_id = self.load_json_data['IE ProductID']

            logger.debug("Microsoft\\Internet Explorer ProductId")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration",
                                        value_name="ProductId",
                                        value_type=RegistryKeyType.REG_SZ,
                                        key_value=self.random_ie_product_id)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['IE Digital ProductID'] == '':
            print ("IE Digital ProductID is not setup")
        else:
            print("load_json_data['IE Digital ProductID']: ", self.load_json_data['IE Digital ProductID'])
            self.random_ie_digital_product_id = ast.literal_eval(self.load_json_data['IE Digital ProductID'])

            logger.debug("Microsoft\\Internet Explorer DigitalProductId")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration",
                                        value_name="DigitalProductId",
                                        value_type=RegistryKeyType.REG_BINARY,
                                        key_value=random_utils.bytes_list_to_array(self.random_ie_digital_product_id))
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['IE Digital ProductID4'] == '':
            print ("IE Digital ProductID4 is not setup")
        else:
            print("load_json_data['IE Digital ProductID4']: ", self.load_json_data['IE Digital ProductID4'])
            self.random_ie_digital_product_id4 = ast.literal_eval(self.load_json_data['IE Digital ProductID4'])
            logger.debug("Internet Explorer\\Registration DigitalProductId")
            ret = registry_helper.write_value(key_hive=hive,
                                        key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration",
                                        value_name="DigitalProductId4",
                                        value_type=RegistryKeyType.REG_BINARY,
                                        key_value=random_utils.bytes_list_to_array(self.random_ie_digital_product_id4))
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
        
        if self.load_json_data['IE Installed Date'] == '':
            print ("IE Installed Date is not setup")
        else:
            print("load_json_data['IE Installed Date']: ", self.load_json_data['IE Installed Date'])
            self.random_ie_installed_date = ast.literal_eval(self.load_json_data['IE Installed Date'])
            logger.debug("Internet Explorer\\Migration IE Installed Date")
            ret = registry_helper.write_value(key_hive=hive,
                                              key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Migration",
                                              value_name="IE Installed Date",
                                              value_type=RegistryKeyType.REG_BINARY,
                                              key_value=random_utils.bytes_list_to_array(self.random_ie_installed_date),
                                              access_type=Wow64RegistryEntry.KEY_WOW32_64)
            if ret == False:
                self.error_dialog.showMessage("Must run as administrator")
                return
            
        self.load_gui_data()
    
    """
    Save all telemetry network hardware ids
    """
    def save_tele_net_hw_setting_json(self):
        if self.checkbox_rd_deviceid.isChecked():
            self.load_json_data['Device id'] = self.device_id_brackets
        
        if self.checkbox_rd_hostname.isChecked():
            self.load_json_data['Hostname'] = self.random_host
        
        if self.checkbox_rd_usename.isChecked():
            self.load_json_data['Username'] = self.random_user
        
        if self.checkbox_rd_hwprofileg.isChecked():
            self.load_json_data['hwprofile guid'] = self.random_hwprofile_guid
        
        if self.checkbox_rd_machineg.isChecked():
            self.load_json_data['machine guid'] = self.random_machine_guid
        
        if self.checkbox_rd_susclientid.isChecked():
            self.load_json_data['susclient id'] = self.random_susclient_id
        
        if self.checkbox_rd_susclientid.isChecked():
            self.load_json_data['susclient id validation'] = str(self.random_susclient_id_valid)
        
        self.save_data_file(self.load_json_data)
    
    """
    Randomize and save telemetry id 
    """
    def randomize_device_id(self):
        self.checkbox_rd_deviceid.setChecked(True)
    
    def rd_device_id(self):
        if self.checkbox_rd_deviceid.isChecked():
            windows_ver = platform_version()
            if not windows_ver.startswith("Windows-10"):
                logger.warning("Telemetry ID replace available for Windows 10 only")
                return

            self.telemetry_fp = telemetry_fingerprint.TelemetryFingerprint()
            self.device_id = self.telemetry_fp.random_device_id_guid()
            self.device_id_brackets = "{%s}" % self.telemetry_fp.random_device_id_guid()
            logger.info("New Windows 10 Telemetry DeviceID is {0}".format(self.device_id_brackets))

            self.text_rddeviceid.setText(self.device_id_brackets)
            self.text_rddeviceid.setCursorPosition(0)
    
    """
    Randomize and save network ids
    """
    def randomize_network_ids(self):
        self.checkbox_rd_hostname.setChecked(True)
        self.checkbox_rd_usename.setChecked(True)

    def rd_hostname(self):
        if self.checkbox_rd_hostname.isChecked():
            self.random_host = random_utils.random_hostname()
            self.text_rdhostname.setText(self.random_host)
            self.text_rdhostname.setCursorPosition(0)
            logger.info("Random hostname value is {0}".format(self.random_host))
    
    def rd_username(self):
        if self.checkbox_rd_usename.isChecked():
            self.random_user = random_utils.random_username()
            self.text_rdusername.setText(self.random_user)
            self.text_rdusername.setCursorPosition(0)
            logger.info("Random username value is {0}".format(self.random_user))
    
    """
    Randomize all hardware ids
    """
    def randomize_hardware_ids(self):
        self.checkbox_rd_hwprofileg.setChecked(True)
        self.checkbox_rd_machineg.setChecked(True)
        self.checkbox_rd_susclientid.setChecked(True)
        self.checkbox_rd_susclientid_vali.setChecked(True)
    
    def rd_hwprofile_guid(self):
        if self.checkbox_rd_hwprofileg.isChecked():
            self.random_hwprofile_guid = hardware_fp.random_hw_profile_guid()
            self.text_rdhwprofileg.setText(self.random_hwprofile_guid)
            self.text_rdhwprofileg.setCursorPosition(0)
            logger.info("Random hwprofile guid value is {0}".format(self.random_hwprofile_guid))
    
    def rd_machine_guid(self):
        if self.checkbox_rd_machineg.isChecked():
            self.random_machine_guid = hardware_fp.random_machine_guid()
            self.text_rdmachineg.setText(self.random_machine_guid)
            self.text_rdmachineg.setCursorPosition(0)
            logger.info("Random machine guid value is {0}".format(self.random_machine_guid))
    
    def rd_susclient_id(self):
        if self.checkbox_rd_susclientid.isChecked():
            self.random_susclient_id = hardware_fp.random_win_update_guid()
            self.text_rdsusclientid.setText(self.random_susclient_id)
            self.text_rdsusclientid.setCursorPosition(0)
            logger.info("Random susclient id value is {0}".format(self.random_susclient_id))
    
    def rd_susclient_id_validation(self):
        if self.checkbox_rd_susclientid.isChecked():
            self.random_susclient_id_valid = hardware_fp.random_client_id_validation()
            self.text_rdsusclientid_vali.setText(str(self.random_susclient_id_valid))
            self.text_rdsusclientid_vali.setCursorPosition(0)
            logger.info("Random susclient id validation value is {0}".format(self.random_susclient_id_valid))
    
    """
    Randomize all system ids
    """
    def randomize_system_ids(self):
        self.checkbox_rd_buildguid.setChecked(True)
        self.checkbox_rd_buildlab.setChecked(True)
        self.checkbox_rd_buildlabex.setChecked(True)
        self.checkbox_rd_build.setChecked(True)
        self.checkbox_rd_build_num.setChecked(True)
        self.checkbox_rd_version.setChecked(True)
        self.checkbox_rd_digi_productid.setChecked(True)
        self.checkbox_rd_digi_productid4.setChecked(True)
        self.checkbox_rd_editionid.setChecked(True)
        self.checkbox_rd_installdate.setChecked(True)
        self.checkbox_rd_productid.setChecked(True)
        self.checkbox_rd_productname.setChecked(True)
        self.checkbox_rd_iesvckb.setChecked(True)
        self.checkbox_rd_ieproductid.setChecked(True)
        self.checkbox_rd_iedigitalpro.setChecked(True)
        self.checkbox_rd_iedigitalpro4.setChecked(True)
        self.checkbox_rd_ieinstalldate.setChecked(True)
    
    """
    Save all window ids
    """
    def save_all_window_ids_json(self):
        if self.checkbox_rd_buildguid.isChecked():
            self.load_json_data['Build guid'] = self.random_build_guid
        
        if self.checkbox_rd_buildlab.isChecked():
            self.load_json_data['Build lab'] = self.random_build_lab
        
        if self.checkbox_rd_buildlabex.isChecked():
            self.load_json_data['Build labex'] = self.random_build_lab_ex
        
        if self.checkbox_rd_build.isChecked():
            self.load_json_data['Current build'] = self.random_build
        
        if self.checkbox_rd_build_num.isChecked():
            self.load_json_data['Current build number'] = self.random_build_num
        
        if self.checkbox_rd_version.isChecked():
            self.load_json_data['Current version'] = self.random_version
        
        if self.checkbox_rd_digi_productid.isChecked():
            self.load_json_data['Digital ProductId'] = str(self.random_digital_product_id)
        
        if self.checkbox_rd_digi_productid4.isChecked():
            self.load_json_data['Digital ProductId4'] = str(self.random_digital_product_id4)
        
        if self.checkbox_rd_editionid.isChecked():
            self.load_json_data['Edition Id'] = str(self.random_edition_id)
        
        if self.checkbox_rd_installdate.isChecked():
            self.load_json_data['Install Date'] = str(self.random_install_date)
        
        if self.checkbox_rd_productid.isChecked():
            self.load_json_data['Product Id'] = str(self.random_product_id)
        
        if self.checkbox_rd_productname.isChecked():
            self.load_json_data['Product Name'] = str(self.random_product_name)
        
        if self.checkbox_rd_iesvckb.isChecked():
            self.load_json_data['IE SvsKB Number'] = str(self.random_ie_svskb_num)
        
        if self.checkbox_rd_ieproductid.isChecked():
            self.load_json_data['IE ProductID'] = str(self.random_ie_product_id)
        
        if self.checkbox_rd_iedigitalpro.isChecked():
            self.load_json_data['IE Digital ProductID'] = str(self.random_ie_digital_product_id)
        
        if self.checkbox_rd_iedigitalpro4.isChecked():
            self.load_json_data['IE Digital ProductID4'] = str(self.random_ie_digital_product_id4)
        
        if self.checkbox_rd_ieinstalldate.isChecked():
            self.load_json_data['IE Installed Date'] = str(self.random_ie_installed_date)
        
        self.save_data_file(self.load_json_data)
    
    def rd_build_guid(self):
        if self.checkbox_rd_buildguid.isChecked():
            self.random_build_guid = system_fp.random_build_guid()
            self.text_rdbuildguid.setText(self.random_build_guid)
            self.text_rdbuildguid.setCursorPosition(0)
            logger.info("Random build GUID {0}".format(self.random_build_guid))
    
    def rd_build_lab(self):
        if self.checkbox_rd_buildlab.isChecked():
            self.random_build_lab = system_fp.random_build_lab()
            self.text_rdbuildlab.setText(self.random_build_lab)
            self.text_rdbuildlab.setCursorPosition(0)
            logger.info("Random BuildLab {0}".format(self.random_build_lab))
    
    def rd_build_lab_ex(self):
        if self.checkbox_rd_buildlabex.isChecked():
            self.random_build_lab_ex = system_fp.random_build_lab_ex()
            self.text_rdbuildlabex.setText(self.random_build_lab_ex)
            self.text_rdbuildlabex.setCursorPosition(0)
            logger.info("Random BuildLabEx {0}".format(self.random_build_lab_ex))
    
    def rd_build(self):
        if self.checkbox_rd_build.isChecked():
            self.random_build = system_fp.random_current_build()
            self.text_rdbuild.setText(self.random_build)
            self.text_rdbuild.setCursorPosition(0)
            logger.info("Random Current Build {0}".format(self.random_build))
    
    def rd_build_num(self):
        if self.checkbox_rd_build_num.isChecked():
            self.random_build_num = system_fp.random_current_build()
            self.text_rdbuild_num.setText(self.random_build_num)
            self.text_rdbuild_num.setCursorPosition(0)
            logger.info("Random Current Build number {0}".format(self.random_build_num))
    
    def rd_version(self):
        if self.checkbox_rd_version.isChecked():
            self.random_version = system_fp.random_current_version()
            self.text_rdversion.setText(self.random_version)
            self.text_rdversion.setCursorPosition(0)
            logger.info("Random Current Version {0}".format(self.random_version))
    
    def rd_digital_product_id(self):
        if self.checkbox_rd_digi_productid.isChecked():
            self.random_digital_product_id = system_fp.random_digital_product_id()
            # self.random_digital_product_id = random_utils.bytes_list_to_array(system_fp.random_digital_product_id())
            self.text_rddigi_productid.setText(str(self.random_digital_product_id))
            self.text_rddigi_productid.setCursorPosition(0)
            logger.info("Random digital product ID {0}".format(self.random_digital_product_id))
    
    def rd_digital_product_id4(self):
        if self.checkbox_rd_digi_productid4.isChecked():
            self.random_digital_product_id4 = system_fp.random_digital_product_id4()
            # self.random_digital_product_id4 = random_utils.bytes_list_to_array(system_fp.random_digital_product_id4())
            self.text_rddigi_productid4.setText(str(self.random_digital_product_id4))
            self.text_rddigi_productid4.setCursorPosition(0)
            logger.info("Random digital product ID 4 {0}".format(self.random_digital_product_id4))
    
    def rd_edition_id(self):
        if self.checkbox_rd_editionid.isChecked():
            self.random_edition_id = system_fp.random_edition_id()
            self.text_rdeditionid.setText(self.random_edition_id)
            self.text_rdeditionid.setCursorPosition(0)
            logger.info("Random Edition ID {0}".format(self.random_edition_id))
    
    def rd_install_date(self):
        if self.checkbox_rd_installdate.isChecked():
            self.random_install_date = system_fp.random_install_date()
            self.text_rdinstalldate.setText(str(self.random_install_date))
            self.text_rdinstalldate.setCursorPosition(0)
            logger.info("Random Install Date {0}".format(self.random_install_date))
    
    def rd_product_id(self):
        if self.checkbox_rd_productid.isChecked():
            self.random_product_id = system_fp.random_product_id()
            self.text_rdproductid.setText(self.random_product_id)
            self.text_rdproductid.setCursorPosition(0)
            logger.info("Random product ID {0}".format(self.random_product_id))
    
    def rd_product_name(self):
        if self.checkbox_rd_productname.isChecked():
            self.random_product_name = system_fp.random_product_name()
            self.text_rdproductname.setText(self.random_product_name)
            self.text_rdproductname.setCursorPosition(0)
            logger.info("Random Product name {0}".format(self.random_product_name))
    
    def rd_IE_SvsKB(self):
        if self.checkbox_rd_iesvckb.isChecked():
            self.random_ie_svskb_num = system_fp.random_ie_service_update()
            self.text_rdiesvckb.setText(self.random_ie_svskb_num)
            self.text_rdiesvckb.setCursorPosition(0)
            logger.info("Random IE service update {0}".format(self.random_ie_svskb_num))
    
    def rd_IE_product_id(self):
        if self.checkbox_rd_ieproductid.isChecked():
            self.random_ie_product_id = system_fp.random_product_id()
            self.text_rdieproductid.setText(self.random_ie_product_id)
            self.text_rdieproductid.setCursorPosition(0)
            logger.info("Random IE product id {0}".format(self.random_ie_product_id))
    
    def rd_IE_digital_product_id(self):
        if self.checkbox_rd_iedigitalpro.isChecked():
            self.random_ie_digital_product_id = system_fp.random_digital_product_id()
            # self.random_ie_digital_product_id = random_utils.bytes_list_to_array(system_fp.random_digital_product_id())
            self.text_rdiedigitalpro.setText(str(self.random_ie_digital_product_id))
            self.text_rdiedigitalpro.setCursorPosition(0)
            logger.info("Random IE digital product id {0}".format(self.random_ie_digital_product_id))
    
    def rd_IE_digital_product_id4(self):
        if self.checkbox_rd_iedigitalpro4.isChecked():
            self.random_ie_digital_product_id4 = system_fp.random_digital_product_id4()
            # self.random_ie_digital_product_id4 = random_utils.bytes_list_to_array(system_fp.random_digital_product_id4())
            self.text_rdiedigitalpro4.setText(str(self.random_ie_digital_product_id4))
            self.text_rdiedigitalpro4.setCursorPosition(0)
            logger.info("Random IE digital product id {0}".format(self.random_ie_digital_product_id4))
    
    def rd_IE_installed_date(self):
        if self.checkbox_rd_ieinstalldate.isChecked():
            self.random_ie_installed_date = system_fp.random_ie_install_date()
            print (f"Decode array: {self.random_ie_installed_date}")
            self.text_rdieinstalldate.setText(str(self.random_ie_installed_date))
            self.text_rdieinstalldate.setCursorPosition(0)
            logger.info("Random IE install data {0}".format(self.random_ie_installed_date))
    

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    Antios = QtWidgets.QDialog()
    ui = Ui_Antios()
    ui.setupUi(Antios)
    Antios.show()
    sys.exit(app.exec_())
