import json
import datetime
import pathlib
import os
from .variable import Variables
import platform


class jsonPrint:
	def __init__(self,  
						filename:str = '',
						rawHex = False,
						current_arch:int = 0,
						sharem_out_dir:str = os.path.join(os.path.dirname(__file__),"..", "logs")
						):
		self.sharem_out_dir = sharem_out_dir
		self.filename = filename
		self.rawHex = rawHex
		self.current_arch = current_arch
		self.slash = "\\" if platform.uname()[0] == "Windows" else "/"
		
		
		#add these in when creating the class
		self.FoundApisName = ''
		# data for output
		self.jsonDissasembly = ''
		self.jsonImports = ''
		self.jsonData: dict[str, list] = {
			"dateAnalyzed":[],
			"classification":[],
			"reason":[],
			"secondsSinceEpoch":[],
			"fileType":[],
			"bits":[],
			"md5":[],
			"ssdeep":[],
			"pushret":[],
			"PEB":[],
			"fstenv":[],
			"heavensGate":[],
			"syscall":[],
			"strings":[],
			"shellcode":[],
			"deobfuscation":[],
			"emulation":[],
			}
		self.emulation_dict: dict[str, list] = { 
			"api_calls":[],
			"syscalls_emulation":[],
			"dlls":[],
			"path_copy":[],
			"path_move":[],
			"path_misc":[],
			"file_hash":[],
			"file_create":[],
			"file_delete":[],
			"file_read":[],
			"file_write":[],
			"file_copy":[],
			"file_move":[],
			"file_misc":[],
			"commandLine_artifacts":[],
			"web_artifacts":[],
			"exe_dll_artifacts":[],
			"registry_actions":[],
			"registry_techniques":[],
			"registry_hierarchy":[],
			"registry_miscellaneous":[]
		}
		#move these into their own class later

#####################
###  remove later ###
#####################
	def checkForLabel(self,addb, labels):
		for label in labels:
			if label==addb:
				val="	 label_"+addb+":\n"
				return True, val
		return False,0

	def importData(self,importedData,FoundApisName,filename,importDiss):
		
		self.jsonData = importedData
		self.FoundApisName = FoundApisName
		self.filename = filename
		self.jsonDissasembly = importDiss
#####################
##  Main Shellcode ##
#####################
	def generateJson(self, filename, peName, sharem_out_dir, rawHex):
		#append the time analyzed to the json
		time = datetime.datetime.now()
		fileNameTime = time.strftime("%Y%m%d_%H%M%S")
		analyzedTime = time.strftime("%Y-%m-%d %H:%M:%S")
		self.jsonData['dateAnalyzed'] = analyzedTime
		
		#create filenames and folder names
		folder_out, default_folder, mainName, importName, dissName, defaultMain, defaultDiss = self.createFileNames(fileNameTime, filename, peName, sharem_out_dir)

		os.makedirs(folder_out, exist_ok=True)
		os.makedirs(default_folder, exist_ok=True)
		
			#write the data to files in the folder
		self.writeJson(mainName,self.jsonData)
		
		if not rawHex:
			self.writeJson(importName,self.jsonImports)
		if rawHex:
			self.writeJson(dissName,self.jsonDissasembly)
			#default files
		self.writeJson(defaultMain,self.jsonData)
		self.writeJson(defaultDiss,self.jsonDissasembly)
		
	def createFileNames(self,fileNameTime, filename,peName, sharem_out_dir):
		#try to extract the file name without the extension, but in the case of no extension we just take the filename as the path
		try:
			fileNameOnly = pathlib.Path(self.filename).stem
		except:
			#filename is taken as the filename
			fileNameOnly = self.filename

		## This fancy stem stuff FAILS with PE files - leaving it with no filename! Thus, this is backup. The above works for shellcode, but if it fails, this will fix it.
		if fileNameOnly=="":
			filename = filename.split(self.slash)[-1]
			if filename == "":
				outfile = peName.split(".")[0]
				outfileName = peName
				if outfileName[-4]==".":
					outfileName=outfileName[:-4]
			else:   
				outfile = filename.split(".")[0]
				outfileName = filename
				if outfileName[-4]==".":
					outfileName=outfileName[:-4]
					# print (outfileName)

			if sharem_out_dir == "current_dir":
				# output_dir = os.path.join(os.path.dirname(__file__), "sharem", "logs")
				output_dir = os.path.join(self.sharem_out_dir)

			else:
				output_dir = sharem_out_dir


			outfileName =  os.path.join(output_dir,  outfileName.split("\\")[-1].strip(), outfileName.split("\\")[-1].strip())

			fileNameOnly=outfileName
		
		folder_out = os.path.join(self.sharem_out_dir,fileNameOnly)

		#create the main json file output name
		if(self.current_arch == 64):
			mainName = fileNameOnly+'-64_'+fileNameTime+'.json'
		else:
			mainName = fileNameOnly+'-32_'+fileNameTime+'.json'
		#create the imports json
		if not self.rawHex:
			importName = fileNameOnly+"-imports_"+fileNameTime+".json"
		else:
			#We have to return someting, so we will return a blank value
			importName = ''
		#create the dissasembly name
		dissName = fileNameOnly+'-disassembly'+'.json'
		
		#default json names
		default_folder = os.path.join(self.sharem_out_dir,'default')
		defaultMain = os.path.join(default_folder,'jsondefault.json')
		defaultDiss = os.path.join(default_folder,'jsondefaultdisasm.json')
		
		mainName = os.path.join(folder_out,mainName)
		importName = os.path.join(folder_out,importName)
		dissName = os.path.join(folder_out,dissName)
		
		return  folder_out, default_folder, mainName, importName, dissName, defaultMain, defaultDiss
		
	def hashes(self,o,sh):
		binLit = ''

		if sh.decryptSuccess:
			for i in sh.decoderStub:
				binLit += '\\x' + '{:02x}'.format(i) +""
			self.jsonData['deobfuscated'] = True

			self.jsonData['decoded_stub'] = binLit
			self.jsonData['md5'] = m[o].getMd5()
			self.jsonData['sha256'] = m[o].getSha256()
			self.jsonData['ssdeep'] = m[o].getSsdeep()

		else:
			self.jsonData['deobfuscated'] = False 
			self.jsonData['decoded_stub'] = 'N/A'
			self.jsonData['md5'] = 'N/A'
			self.jsonData['sha256'] = 'N/A'
			self.jsonData['ssdeep'] = 'N/A'

	def generateEmulationResults(self,apiList,logged_syscalls,em,art):
		self.apis(apiList)
		self.syscalls(logged_syscalls,em)
		self.artifacts(art,apiList)

		return self.emulation_dict

	def generateDisassemblyResults(self,Colors=True, caller=None,decoder=False):
		#import off_Label,labels,res,sBy
		red,gre,yel,blu,mag,cya,whi,res,res2 = self.variableGlobals.colors()
		# maxOpDisplay=self.variableGlobals.mBool[self.variableGlobals.o].maxOpDisplay
		Variables().mBool
		
#####################
####    Output   ####
#####################
	def writeJson(self,filePath,jsonData):
		if(filePath == ''):
			return
		#for the disassembly, as it is passed as a str.
		#   update disassembly to pass as a dict later
		if(type(jsonData) == str):
			with open(filePath,'w') as f:
				f.write(jsonData)
				return
		with open(filePath,'w') as f:
			#format this jsonDumps library.
			f.write(json.dumps(jsonData,separators=(',',':'),indent=1))
#####################
####  Emulation  ####
#####################
	def apis(self,apiList):
		api_dict = {}
		for i in apiList:
			tuple_flag = 0
			api_name = i[0]
			api_address = i[1]
			ret_value = i[2]
			ret_type = i[3]
			try:
				dll_name = i[8]
			except:
				dll_name = "kernel32.dll"
				
			api_dict.update({'api_name':api_name})
			api_dict["dll_name"] = dll_name
			api_dict["return_value"]= ret_type+" " + str(ret_value)
			api_dict["address"] = api_address
			api_dict['parameters'] = []

			api_params_values = i[4]
			api_params_types = i[5]
			api_params_names = i[6]
			for potentialTuple in api_params_values:
				if( type(potentialTuple) == tuple):
					# print("is a tuple")
					# print(potentialTuple)
					tuple_flag = 1
					
			if (tuple_flag == 1):
				api_dict.update(self.jsonTuples(api_params_values,api_params_types,api_params_names,api_dict))
			else:
				# for pTyp, pName, pVal in zip(api_params_types, api_params_names, api_params_values):
				# 	api_dict['parameters'].append({"type":pTyp + " " + pName,
				# 								"value":str(pVal)})
				p = 0
				for pName in api_params_names:
					api_type_value = []
					api_type_value.append({"type":api_params_types[p],
												"value":str(api_params_values[p])})
					api_dict['parameters'].append({"type":api_params_names[p],
												"value":api_type_value})
					p+=1
			# list_of_apis.append(api_dict)
		self.emulation_dict['api_calls'].append(api_dict)

	def syscalls(self,logged_syscalls,em):
		var = Variables()
		# syscalls_dict = {}
		# print(var.logged_syscalls)
		for i in var.logged_syscalls:
			# print(i)
			tuple_flag = 0
			# print(type(i))
			# print(i)
			syscalls_dict = {}
			
			syscall_name = i[0]
			syscall_address = i[1]
			syscall_value = i[2]
			syscall_type = i[3]
			syscall_params_values = i[4]
			syscall_params_types = i[5]
			syscall_params_names = i[6]
			syscall_callID = i[8]
			for potentialTuple in syscall_params_values:
				if( type(potentialTuple) == tuple):
					tuple_flag = 1
			syscalls_dict["syscall_name"] = str(syscall_name)
			syscalls_dict["return_value"] = str(syscall_type + " "+syscall_value)
			syscalls_dict["address"] = str(syscall_address)
			syscalls_dict['parameters'] = []
			
			if (tuple_flag == 1):
				syscalls_dict.update(self.jsonTuples(syscall_params_values,syscall_params_types,syscall_params_names,syscalls_dict))
			else:
				p = 0
				for pName in syscall_params_names:
					syscall_type_value = []
					syscall_type_value.append({"type":syscall_params_types[p],
												"value":str(syscall_params_values[p])})
					syscalls_dict['parameters'].append({"type":syscall_params_names[p],
												"value":syscall_type_value})
					p+=1
		


				# for pTyp, pName, pVal in zip(syscall_params_types, syscall_params_names, syscall_params_values):
				#     syscalls_dict['parameters'].append({"type":str(pTyp) + " " + str(pName),
				#                                         "value":str(pVal)})

			syscalls_dict["syscall_callID"] = str(hex(syscall_callID))
			syscalls_dict["OS_Release_SP"] = var.emu.winVersion+", SP "+var.emu.winSP

			# self.emulation_dict['syscalls_emulation'] = syscalls_dict
			self.emulation_dict['syscalls_emulation'].append(syscalls_dict)

	def artifacts(self,art,apiList):
		self.dlls(apiList)
		self.emulation_dict["path_misc"].extend(art.path_artifacts)
		self.paths(art)
		self.files(art)
		self.emulation_dict["commandLine_artifacts"].extend(art.commandLine_artifacts)
		self.emulation_dict["web_artifacts"].extend(art.web_artifacts)
		self.emulation_dict["exe_dll_artifacts"].extend(art.exe_dll_artifacts)
		self.registry(art)
		
	def dlls(self,logged_dlls):
		dllList = set()
		if(len(logged_dlls) >0):
			for each in logged_dlls:
				try:
					dll_name = each[8]
				except:
					dll_name = "kernel32.dll"
				dllList.add(dll_name)
					
		self.emulation_dict['dlls'] = list(dllList)
#-------------------
#     Paths 
#-------------------
	def paths(self,art):
		self.fileSysetemMovement(art.path_copy,'path_copy')
		self.fileSysetemMovement(art.path_move,'path_move')
		self.emulation_dict['path_misc'].extend(art.path_artifacts)


#-------------------
#     Files 
#-------------------
	def files(self,art):
		self.emulation_dict["file_misc"].extend(art.file_artifacts)	
		self.emulation_dict["file_create"].extend(art.files_create)	
		self.emulation_dict["file_delete"].extend(art.files_delete)	
		self.emulation_dict["file_read"].extend(art.files_access)	
		self.emulation_dict["file_write"].extend(art.files_write)
		self.fileSysetemMovement(art.files_copy,'file_copy')
		self.fileSysetemMovement(art.files_move,'file_move')
		self.filehashes(art.files_hashes,'file_hash')

#-------------------
#     Registry 
#-------------------
	def registry(self,art):
		self.emulation_dict["registry_miscellaneous"].extend(art.registry_misc)
		self.registryActions(art)
		self.registryTechniques(art)
		self.registryHierarchy(art)

	def registryActions(self,art):
		registryActionsDict = {}

		addedKeysList = []
		editedKeysList = []
		deletedKeysList = []
		for i in art.registry_add_keys:
			addedKeysList.append({"key_path":i,
									"value":""})
		for i in art.registry_edit_keys:
			editedKeysList.append({"key_path":i[0],
									"value":str([i[1],i[2]])})
		for i in art.registry_delete_keys:
			if(type(i) == tuple):
				deletedKeysList.append({"key_path":i[0],
									"value":str(i[1])})
			else:
				deletedKeysList.append({"key_path":i,
									"value":""})

		registryActionsDict["added_keys"] = addedKeysList
		registryActionsDict["edited_keys"] = editedKeysList
		registryActionsDict["deleted_keys"] = deletedKeysList

		self.emulation_dict['registry_actions'].extend(registryActionsDict)

	def registryTechniques(self,art):
		registryTechniquesDict = {}
		persistence_list = []
		credentials_list = []
		discovery_list = []
		for i in art.registry_persistence:
			persistence_list.append({"key_path": i})
		for i in art.registry_credentials:
			credentials_list.append({"key_path": i})
		for i in art.registry_discovery:
			discovery_list.append({"key_path": i})
		registryTechniquesDict["persistence"] = persistence_list
		registryTechniquesDict["credentials"] = credentials_list
		registryTechniquesDict["discovery"] = discovery_list
		self.emulation_dict["registry_techniques"].extend(registryTechniquesDict)

	def registryHierarchy(self,art):
		registryHierarchyDict = {}
		classes_root_keys = []
		current_user_keys = []
		local_machine_keys = []
		users_keys = []
		current_config_keys = []
		for i in art.reg_HKCR:
			classes_root_keys.append({"key_path":i})
		for i in art.reg_HKCU:
			current_user_keys.append({"key_path":i})
		for i in art.reg_HKLM:
			local_machine_keys.append({"key_path":i})
		for i in art.reg_HKU:
			users_keys.append({"key_path":i})
		for i in art.reg_HKCC:
			current_config_keys.append({"key_path":i})

		registryHierarchyDict["hkey_classes_root"] = classes_root_keys
		registryHierarchyDict["hkey_current_user"] = current_user_keys
		registryHierarchyDict["hkey_local_machine"] = local_machine_keys
		registryHierarchyDict["hkey_users"] = users_keys
		registryHierarchyDict["hkey_current_config"] = current_config_keys

		self.emulation_dict["registry_hierarchy"].extend(registryHierarchyDict)

#####################
####   Helpers   ####
#####################
	def fileSysetemMovement(self,artCategory,emuDest):
		for each in artCategory:
			each = list(each)
			Dict = {}
			Dict.update({'origin':each[0]})
			Dict.update({'destination':each[1]})
			self.emulation_dict[emuDest].append(Dict)
			
	def filehashes(self,artCategory,emuDest):
		for each in artCategory:
			each = list(each)
			Dict = {}
			Dict.update({'file':each[0]})
			Dict.update({'hash':each[1]})
			self.emulation_dict[emuDest].append(Dict)

	def jsonTuples(self,paramValues,params_types,params_names,dictName):
		t = 0
		for pv in paramValues:
			if isinstance(paramValues[t], tuple):
				struct_values_list = []
				struct_name = paramValues[t][0]
				struct_type = paramValues[t][1]
				struct_value = paramValues[t][2]
				i = 0
				for each in struct_value:
					#found a union sturcutre
					if('{' in each):
						each = each[1:-1]
						each = each.split(',')
						
						# struct_value[i] = str(each)
						struct_value[i] = each
					i+=1
				for sType, sName, sVal in zip(struct_name, struct_type, struct_value):
					struct_values_list.append({"structure_type":sType + " " + sName,
												"structure_value":str(sVal)})
				dictName['parameters'].append({"type":params_types[t] + " " + params_names[t],
										"value":struct_values_list})
				
			else:
				type_value = []
				type_value.append({"type":params_types[t],
									"value":str(paramValues[t])})
				dictName['parameters'].append({"type":params_names[t],
										"value":type_value})
			t+= 1
		return dictName

	def checkStr(self,dllList):
		checkedList =  dllList
		i = 0
		for item in dllList:
			checkedList[i] = list(item)
			checkedList[i][-1] = str(checkedList[i][-1])
			i+=1
		return checkedList

############################################################################################
############################			Documentation			############################
############################################################################################
#