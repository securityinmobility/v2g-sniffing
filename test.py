from external_libraries.HomePlugPWN.layerscapy.HomePlugAV import ModulePIB

file = r'C:\Users\eder\Nextcloud\Lukas\01_Studium\Master\Semester2\Projekt\pib_files\eva_evse.pib'

data = open(file, "rb").read()

ModulePIB(data[0x3C0:]).show()