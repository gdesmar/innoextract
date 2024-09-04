/*
 * Based on https://github.com/WhatTheBlock/innounp/blob/main/src/RebuildScript.pas
 */

#include "cli/iss.hpp"

#include <ctime>
#include <iostream>
#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include "setup/component.hpp"
#include "setup/data.hpp"
#include "setup/delete.hpp"
#include "setup/directory.hpp"
#include "setup/file.hpp"
#include "setup/header.hpp"
#include "setup/icon.hpp"
#include "setup/info.hpp"
#include "setup/ini.hpp"
#include "setup/item.hpp"
#include "setup/language.hpp"
#include "setup/message.hpp"
#include "setup/permission.hpp"
#include "setup/registry.hpp"
#include "setup/run.hpp"
#include "setup/task.hpp"
#include "setup/type.hpp"
#include "setup/version.hpp"

#include "stream/block.hpp"

#include "util/fstream.hpp"
#include "util/load.hpp"
#include "util/log.hpp"
#include "util/output.hpp"
#include "util/time.hpp"

namespace fs = boost::filesystem;

namespace iss {

struct SectionHeader {
	const std::string & name;
	const bool prepend_empty_line;
	
	SectionHeader(const std::string & _name)
		: name(_name), prepend_empty_line(true) { }

	SectionHeader(const std::string & _name, const bool _prepend_empty_line)
		: name(_name), prepend_empty_line(_prepend_empty_line) { }
	
};

inline std::ostream & operator<<(std::ostream & os, const SectionHeader & s) {
	if(s.prepend_empty_line) {
		return os << '\n' << '[' << s.name << ']' << '\n';
	}
	return os << '[' << s.name << ']' << '\n';
}

struct StrConst {
	const std::string & name;
	const std::string & value;
	const bool show_always;
	
	StrConst(const std::string & _name, const std::string & _value)
		: name(_name), value(_value), show_always(false) { }

	StrConst(const std::string & _name, const std::string & _value, const bool _show_always)
		: name(_name), value(_value), show_always(_show_always) { }
	
};

inline std::ostream & operator<<(std::ostream & os, const StrConst & s) {
	if(s.show_always || !s.value.empty()) {
		return os << s.name << '=' << s.value << '\n';
	} else {
		return os;
	}
}

static std::string GetInnoVersionStr(const setup::version & version) {
	std::ostringstream oss;
	
	oss << version.a() << '.' << version.b() << '.' << version.c();
	if(version.d()) {
		oss << '.' << version.d();
	}
	
	if(version.is_unicode()) {
		oss << " (Unicode)";
	}
	
	return oss.str();
}

static std::string Hash2Str(const crypto::checksum & checksum) {
	std::ostringstream oss;

	switch(checksum.type) {
		case crypto::None:
			oss << "(no checksum)";
			break;
		case crypto::Adler32:
			oss << "0x" << std::hex << std::setw(8) << checksum.adler32;
			break;
		case crypto::CRC32:
			oss << "0x" << std::hex << std::setw(8) << checksum.crc32;
			break;
		case crypto::MD5:
			for(size_t i = 0; i < size_t(std::size(checksum.md5)); i++) {
				oss << std::setfill('0') << std::hex << std::setw(2) << int(boost::uint8_t(checksum.md5[i]));
			}
			break;
		case crypto::SHA1:
			for(size_t i = 0; i < size_t(std::size(checksum.sha1)); i++) {
				oss << std::setfill('0') << std::hex << std::setw(2) << int(boost::uint8_t(checksum.sha1[i]));
			}
			break;
	}

	return oss.str();
}

static std::string Salt2Str(const std::string & salt) {
	char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	std::ostringstream oss;
	size_t i = 0;
	if (salt.compare(0, 17, "PasswordCheckHash") == 0) {
		i = 17;
	}
	for(; i < salt.length(); i++) {
		oss << hex_chars[ ( salt[i] & 0xF0 ) >> 4 ];
		oss << hex_chars[ ( salt[i] & 0x0F ) >> 0 ];
	}
	return oss.str();
}

static std::string ProcArcsToStr(const setup::header::architecture_types & architectures) {
	std::ostringstream oss;

	// This is not in the original file
	if (architectures & setup::header::ArchitectureUnknown){
		oss << "unknown ";
	}
	if (architectures & setup::header::X86){
		oss << "x86 ";
	}
	if (architectures & setup::header::Amd64){
		oss << "x64 ";
	}
	if (architectures & setup::header::IA64){
		oss << "ia64 ";
	}
	// This is not in the original file
	if (architectures & setup::header::ARM64){
		oss << "arm64 ";
	}
	
	return boost::trim_right_copy(oss.str());
}

static std::string Priv2Str(const setup::header::privilege_level & privileges_required){
	std::ostringstream oss;

	switch(privileges_required) {
		case setup::header::NoPrivileges:
			oss << "none";
			break;
		case setup::header::PowerUserPrivileges:
			oss << "poweruser";
			break;
		case setup::header::AdminPrivileges:
			break;
		case setup::header::LowestPrivileges:
			oss << "lowest";
			break;
	}

	return oss.str();
}

static std::string DisPage2Str(const setup::header::auto_bool & auto_bool){
	std::ostringstream oss;

	switch(auto_bool) {
		case setup::header::Auto:
			oss << "auto";
			break;
		case setup::header::No:
			oss << "no";
			break;
		case setup::header::Yes:
			oss << "yes";
			break;
	}

	return oss.str();
}

static std::string MaybeToRtf(const std::string & name, const std::string & content){
	std::ostringstream oss;

	oss << name;

	if (content.compare(0, 5, "{\\rtf") == 0) {
		oss << ".rtf";
	} else {
		oss << ".txt";
	}

	return oss.str();
}

static std::string GetWizardImageFileName(size_t index, const bool is_small) {
	std::ostringstream oss;
	if (is_small){
		oss << "WizardSmallImage" << index << ".bmp";
		return oss.str();
	}
	oss << "WizardImage" << index << ".bmp";
	return oss.str();
}

static std::string GetImageFileList(std::vector<std::string> wizard_images, const bool is_small){
	if (wizard_images.empty()){
		return "";
	}
	
	std::ostringstream oss;

	for(size_t i = 0; i < wizard_images.size(); i++) {
		if (i != 0){
			oss << ',';
		}
		oss << "embedded\\" << GetWizardImageFileName(i, is_small);
	}
	
	return oss.str();
}

static void print_header(util::ofstream & ofs, const setup::info & info, const fs::path & installer) {
	const setup::header & header = info.header;

	ofs << StrConst(";InnoSetupVersion", GetInnoVersionStr(info.listed_version));

	ofs << SectionHeader("Setup");
	ofs << StrConst("AppName", header.app_name, true);
	ofs << StrConst("AppVerName", header.app_versioned_name);
	ofs << StrConst("AppId", header.app_id, true);
	ofs << StrConst("AppVersion", header.app_version);
	ofs << StrConst("AppPublisher", header.app_publisher);
	ofs << StrConst("AppPublisherURL", header.app_publisher_url);
	ofs << StrConst("AppSupportPhone", header.app_support_phone);
	ofs << StrConst("AppSupportURL", header.app_support_url);
	ofs << StrConst("AppUpdatesURL", header.app_updates_url);
	ofs << StrConst("AppMutex", header.app_mutex);
	ofs << StrConst("AppComments", header.app_comments);
	ofs << StrConst("AppModifyPath", header.app_modify_path);
	if (header.options & setup::header::CreateAppDir) {
		ofs << StrConst("DefaultDirName", header.default_dir_name);
	} else {
		ofs << StrConst("CreateAppDir", "no");
	}
	if (header.default_group_name != "(Default)") {
		ofs << StrConst("DefaultGroupName", header.default_group_name);
	}
	ofs << StrConst("UninstallDisplayIcon", header.uninstall_icon);
	ofs << StrConst("UninstallDisplayName", header.uninstall_name);
	if (header.uninstall_files_dir != "{app}") {
		ofs << StrConst("UninstallFilesDir", header.uninstall_files_dir);
	}
	// This logic is different from the original, but trying to be close enough
	if (header.base_filename != "") {
		ofs << StrConst("OutputBaseFilename", header.base_filename);
	}
	else {
		std::string installer_string = installer.filename().string();
		if (installer_string.length() >= 4 && installer_string.compare(installer_string.length() - 4, 4, ".exe") == 0) {
			installer_string.erase(installer_string.length() - 4);
		}
		ofs << StrConst("OutputBaseFilename", installer_string);
	}
	switch(header.compression) {
		case stream::Stored:
    		ofs << StrConst("Compression", "none");
			break;
		case stream::Zlib:
    		ofs << StrConst("Compression", "zip");
			break;
		case stream::BZip2:
    		ofs << StrConst("Compression", "bzip2");
			break;
		case stream::LZMA1:
    		ofs << StrConst("Compression", "lzma");
			break;
		case stream::LZMA2:
    		ofs << StrConst("Compression", "lzma2");
			break;
		// This is not in the original file
		case stream::UnknownCompression:
    		ofs << StrConst("Compression", "unknown");
			break;
		default:
			break;
	}
	if (header.options & setup::header::EncryptionUsed) {
		ofs << StrConst("; Encryption", "yes");
	}
	if (info.version > INNO_VERSION_EXT(4, 2, 0, 2) && ((header.options & setup::header::EncryptionUsed) || (header.options & setup::header::Password))) {
		ofs << StrConst("; PasswordHash", Hash2Str(header.password));
		ofs << StrConst("; PasswordSalt", Salt2Str(header.password_salt));
	}
	// https://github.com/WhatTheBlock/innounp/blob/main/src/StructTemplate.pas#L591 only use those in version 5100 and higher
	// Setting architecture_types::all() in header.cpp if lower
	if (info.version >= INNO_VERSION(5, 1, 0)) {
		ofs << StrConst("ArchitecturesAllowed", ProcArcsToStr(header.architectures_allowed));
		ofs << StrConst("ArchitecturesInstallIn64BitMode", ProcArcsToStr(header.architectures_installed_in_64bit_mode));
	}
	if (info.version > INNO_VERSION(5, 3, 1) && !(header.options & setup::header::Uninstallable)) {
		ofs << StrConst("Uninstallable", "no");
	}
	else if(header.uninstallable != "yes"){
		ofs << StrConst("Uninstallable", header.uninstallable);
	}
	if (header.privileges_required != setup::header::AdminPrivileges) {
		ofs << StrConst("PrivilegesRequired", Priv2Str(header.privileges_required));
	}
	if (header.extra_disk_space_required > 0){
		ofs << StrConst("ExtraDiskSpaceRequired", boost::lexical_cast<std::string>(header.extra_disk_space_required));
	}
	if (header.disable_dir_page != setup::header::No){
		ofs << StrConst("DisableDirPage", DisPage2Str(header.disable_dir_page));
	}
	if (header.disable_program_group_page != setup::header::No){
		ofs << StrConst("DisableProgramGroupPage", DisPage2Str(header.disable_program_group_page));
	}
	if (header.options & setup::header::ChangesAssociations)
	{
		ofs << StrConst("ChangesAssociations", "yes");
	}
	if (header.options & setup::header::AllowNoIcons)
	{
		ofs << StrConst("AllowNoIcons", "yes");
	}
	if (header.license_text != ""){
		ofs << StrConst("LicenseFile", MaybeToRtf("embedded\\License", header.license_text));
	}
	if (header.info_before != ""){
		ofs << StrConst("InfoBeforeFile", MaybeToRtf("embedded\\InfoBefore", header.info_before));
	}
	if (header.info_after != ""){
		ofs << StrConst("InfoAfterFile", MaybeToRtf("embedded\\InfoAfter", header.info_after));
	}
	ofs << StrConst("WizardImageFile", GetImageFileList(info.wizard_images, false));
	ofs << StrConst("WizardSmallImageFile", GetImageFileList(info.wizard_images_small, true));
	
	// https://github.com/WhatTheBlock/innounp/blob/main/src/innounp.dpr#L565 seFileLocation are handled as data_entries
	for(size_t i = 0; i < info.data_entries.size(); i++) {
		if ((info.data_entries[i].options & setup::data_entry::TimeStampInUTC) != 0) {
			ofs << StrConst(";TimeStampsInUTC", "yes");
			break;
		}
	}
}

static void StrParam(util::ofstream & ofs, const std::string & display_name,
					 const std::string & value, const bool quotes = true) {
	if (value == ""){
		return;
	}
	if (quotes){
		ofs << display_name << ": \"" << boost::replace_all_copy(value, "\"", "\"\"") << "\"; ";
	} else {
		ofs << display_name << ": " << value << "; ";
	}
}

static void IntParam(util::ofstream & ofs, const std::string & display_name, const boost::uint64_t & value, const bool quotes = true) {
	if (value == 0){
		return;
	}
	StrParam(ofs, display_name, boost::lexical_cast<std::string>(value), quotes);
}

static void IntParam(util::ofstream & ofs, const std::string & display_name, const int & value, const bool quotes = true) {
	if (value == 0){
		return;
	}
	StrParam(ofs, display_name, boost::lexical_cast<std::string>(value), quotes);
}

static std::string VerToStr(const setup::windows_version::data & cardinal, const setup::windows_version::service_pack & service_pack) {
	std::ostringstream oss;

	auto digits = 2;
	auto minor = cardinal.minor;
	if (minor % 10 == 0) {
		digits--;
		minor = minor / 10;
	}
	char current_fill = oss.fill();
	oss << cardinal.major << '.' << std::setfill('0') << std::setw(digits) << minor << std::setfill(current_fill);

	if (cardinal.build != 0) {
		oss << '.' << cardinal.build;
	}

	if (service_pack.major != 0) {
		oss << " Service Pack " << service_pack.major;
		if (service_pack.minor != 0) {
			oss << '.' << service_pack.minor;
		}
	}

	return oss.str();
}

static bool VerOver04000000(const setup::windows_version::data & cardinal) {
	if (cardinal.major > 4) {
		return true;
	}
	if (cardinal.major < 4) {
		return false;
	}
	if (cardinal.minor != 0) {
		return true;
	}
	return cardinal.build != 0;
}

static void PrintVersions(util::ofstream & ofs, const setup::windows_version_range & winver) {
	setup::windows_version::service_pack s_pack = { 0, 0 };

	if (VerOver04000000(winver.begin.win_version) || VerOver04000000(winver.begin.nt_version)) {
    	StrParam(ofs, "MinVersion", VerToStr(winver.begin.win_version, s_pack) + ',' + VerToStr(winver.begin.nt_version, winver.begin.nt_service_pack), false);
	}

	if ((winver.end.win_version.major != 0 && winver.end.win_version.minor != 0) || (winver.end.nt_version.major != 0 && winver.end.nt_version.minor != 0)) {
		StrParam(ofs, "OnlyBelowVersion", VerToStr(winver.end.win_version, s_pack) + ',' + VerToStr(winver.end.nt_version, winver.end.nt_service_pack), false);
	}
}

static void PrintItem(util::ofstream & ofs, const setup::item & item, const bool & print_version=true, const bool & check_quotes=true) {
    StrParam(ofs, "Components", item.components, false);
    StrParam(ofs, "Tasks", item.tasks, false);
    StrParam(ofs, "Languages", item.languages);
    StrParam(ofs, "Check", item.check, check_quotes);
    StrParam(ofs, "BeforeInstall", item.before_install);
    StrParam(ofs, "AfterInstall", item.after_install);
	
	if (print_version) {
		PrintVersions(ofs, item.winver);
	}
}

static std::string FileOpt2Str(const setup::file_entry::flags::enum_type & option) {
	switch(option) {
		case setup::file_entry::ConfirmOverwrite:
			return "confirmoverwrite";
		case setup::file_entry::NeverUninstall:
			// In the original code, it was Excluding it before calling FileOpt2Str, so we'll just ignore it
			// return "uninsneveruninstall";
			return "";
		case setup::file_entry::RestartReplace:
			return "restartreplace";
		case setup::file_entry::DeleteAfterInstall:
			return "deleteafterinstall";
		case setup::file_entry::RegisterServer:
			return "regserver";
		case setup::file_entry::RegisterTypeLib:
			return "regtypelib";
		case setup::file_entry::SharedFile:
			return "sharedfile";
		case setup::file_entry::CompareTimeStamp:
			return "comparetimestamp";
		case setup::file_entry::FontIsNotTrueType:
			return "fontisnttruetype";
		case setup::file_entry::SkipIfSourceDoesntExist:
			return "skipifsourcedoesntexist";
		case setup::file_entry::OverwriteReadOnly:
			return "overwritereadonly";
		case setup::file_entry::OverwriteSameVersion:
			return "";
		case setup::file_entry::CustomDestName:
			return "";
		case setup::file_entry::OnlyIfDestFileExists:
			return "onlyifdestfileexists";
		case setup::file_entry::NoRegError:
			return "noregerror";
		case setup::file_entry::UninsRestartDelete:
			return "uninsrestartdelete";
		case setup::file_entry::OnlyIfDoesntExist:
			return "onlyifdoesntexist";
		case setup::file_entry::IgnoreVersion:
			return "ignoreversion";
		case setup::file_entry::PromptIfOlder:
			return "promptifolder";
		case setup::file_entry::DontCopy:
			return "dontcopy";
		case setup::file_entry::UninsRemoveReadOnly:
			return "uninsremovereadonly";
		case setup::file_entry::RecurseSubDirsExternal:
			return "";
		case setup::file_entry::Bits32:
			return "32bit";
		case setup::file_entry::Bits64:
			return "64bit";
		case setup::file_entry::ExternalSizePreset:
			return "";
		case setup::file_entry::SetNtfsCompression:
			// Typo in the original code
			return "setntfscompression";
		case setup::file_entry::UnsetNtfsCompression:
			return "unsetntfscomptression";
		case setup::file_entry::GacInstall:
			return "gacinstall";
		case setup::file_entry::ReplaceSameVersionIfContentsDiffer:
		case setup::file_entry::DontVerifyChecksum:
		case setup::file_entry::UninsNoSharedFilePrompt:
		case setup::file_entry::CreateAllSubDirs:
		default:
			return "";
	}
}

static std::string RemoveBackslashUnlessRoot(const std::string & path) {
	if (path.length() < 3) {
		return path;
	}
	if (path[1] == ':' && path[2] == '\\') {
		return path;
	}
	if (path.back() == '\\') {
		return path.substr(0, path.length()-1);
	}
	return path;
}

// Based on https://github.com/WhatTheBlock/innounp/blob/main/src/SetupLdr.pas
// Very far from a perfect reimplementation, but that may suffice for now
// Redistributes file name parameters to how they are in the iss script (DestName => Source,DestDir(,DestName))
static void RenameFiles(util::ofstream & ofs, const setup::file_entry & entry) {

	std::string destname;
	std::string source;
	std::string destdir = "";

	destname = boost::replace_all_copy(entry.destination, "\\\\", "\\");
	destname = boost::replace_all_copy(destname, "{{", "{");
	destname = boost::replace_all_copy(destname, "/", "\\");
	// filter out the inappropriate characters
	if (entry.type & setup::file_entry::UninstExe) {
		destname = "embedded\\uninstall.exe";
	} else if (entry.type & setup::file_entry::RegSvrExe) {
		destname = "embedded\\regsvr.exe";
	}

	// Even if read from the file, this looks to be unconditionally overwritten
	source = destname;
	
	size_t last_sep = destname.find_last_of("\\");
	if (last_sep != std::string::npos) {
		destdir = destname.substr(0, last_sep);
		destname = destname.substr(last_sep + 1);
	}

	for(size_t i = 0; i < source.length(); i++) {
		if (strchr(",:*?\"<>|", source[i])) {
			source[i] = '_';
		}
	}

	last_sep = source.find_last_of("\\");
	if (last_sep != std::string::npos && destname == source.substr(last_sep + 1)) {
		destname = "";
	}

	StrParam(ofs, "Source", source);
	StrParam(ofs, "DestDir", RemoveBackslashUnlessRoot(destdir));
	StrParam(ofs, "DestName", destname);
}

static void print_entry(util::ofstream & ofs, const setup::info & info,
						size_t i, const setup::file_entry & entry) {
	(void)info, (void)i;

	if (entry.type != setup::file_entry::UserFile) {
		return;
	}

	// The following chunk of code comes from the original RebuildScript.pas file
	// https://github.com/WhatTheBlock/innounp/blob/main/src/RebuildScript.pas#L736
	// TODO: Find an example to assist with the addition of this comment
	/*
	if (entry.location != -1) {
		with PSetupFileLocationEntry(Entries[seFileLocation][LocationEntry])^ do begin
			if FirstSlice<>LastSlice then
				PrintComment('the following file spans ' + GetSliceName(FirstSlice) + ' to ' + GetSliceName(LastSlice))
			else if FirstSlice<>CurSlice then
				PrintComment('the following file starts on ' + GetSliceName(FirstSlice));
			CurSlice:=LastSlice;
	} else {
		ofs << "; ";
	}
	*/

	RenameFiles(ofs, entry);
	StrParam(ofs, "FontInstall", entry.install_font_name);
	PrintItem(ofs, entry);

	std::ostringstream oss;
	if(entry.options) {
		for(size_t o_i = 0; o_i < setup::file_entry::flags::bits; o_i++) {
			if(entry.options & setup::file_entry::flags::enum_type(o_i)) {
				std::string o_s = FileOpt2Str(setup::file_entry::flags::enum_type(o_i));
				if (o_s != ""){
					oss << o_s << ' ';
				}
			}
		}
	}
	std::string s = oss.str();
	if (s != "") {
		ofs << "Flags: " << s;
	}
	ofs << '\n';
}


static std::string DirOpt2Str(const setup::directory_entry::flags::enum_type & option) {
	switch(option) {
		case setup::directory_entry::NeverUninstall:
			return "uninsneveruninstall";
		case setup::directory_entry::DeleteAfterInstall:
			return "deleteafterinstall";
		case setup::directory_entry::AlwaysUninstall:
			return "uninsalwaysuninstall";
		case setup::directory_entry::SetNtfsCompression:
			return "setntfscomptression";
		case setup::directory_entry::UnsetNtfsCompression:
			return "unsetntfscomptression";
		default:
			return "";
	}
}

static void print_entry(util::ofstream & ofs, const setup::info & info,
                        size_t i, const setup::directory_entry & entry) {
	(void)info, (void)i;

    StrParam(ofs, "Name", entry.name);

	std::ostringstream oss;
	if(entry.options) {
		for(size_t o_i = 0; o_i < setup::directory_entry::flags::bits; o_i++) {
			if(entry.options & setup::directory_entry::flags::enum_type(o_i)) {
				std::string o_s = DirOpt2Str(setup::directory_entry::flags::enum_type(o_i));
				if (o_s != ""){
					oss << o_s << ' ';
				}
			}
		}
	}
	std::string s = oss.str();
	if (s != "") {
		ofs << "Flags: " << s;
	}
	ofs << '\n';
}


static std::string RegRootToStr(const setup::registry_entry & entry) {
	std::ostringstream oss;

	switch(entry.hive) {
		case setup::registry_entry::HKCR:
			oss << "HKCR";
			break;
		case setup::registry_entry::HKCU:
			oss << "HKCU";
			break;
		case setup::registry_entry::HKLM:
			oss << "HKLM";
			break;
		case setup::registry_entry::HKU:
			oss << "HKU";
			break;
		// Not in the original code
		case setup::registry_entry::HKPD:
			oss << "HKPD";
			break;
		case setup::registry_entry::HKCC:
			oss << "HKCC";
			break;
		// Not in the original code
		case setup::registry_entry::HKDD:
			oss << "HKDD";
			break;
		case setup::registry_entry::Unset:
		default:
			break;
	}

	if (entry.options & setup::registry_entry::Bits32) {
		oss << "32";
	}
	else if (entry.options & setup::registry_entry::Bits64) {
		oss << "64";
	}

	return oss.str();
}

static std::string RegistryOpt2Str(const setup::registry_entry::flags::enum_type & option) {
	switch(option) {
		case setup::registry_entry::CreateValueIfDoesntExist:
			return "createvalueifdoesntexist";
		case setup::registry_entry::UninsDeleteValue:
			return "uninsdeletevalue";
		case setup::registry_entry::UninsClearValue:
			return "uninsclearvalue";
		case setup::registry_entry::UninsDeleteEntireKey:
			return "uninsdeletekey";
		case setup::registry_entry::UninsDeleteEntireKeyIfEmpty:
			return "uninsdeletekeyifempty";
		case setup::registry_entry::PreserveStringType:
			return "preservestringtype";
		case setup::registry_entry::DeleteKey:
			return "deletekey";
		case setup::registry_entry::DeleteValue:
			return "deletevalue";
		case setup::registry_entry::NoError:
			return "noerror";
		case setup::registry_entry::DontCreateKey:
			return "dontcreatekey";
		case setup::registry_entry::Bits32:
		case setup::registry_entry::Bits64:
		default:
			return "";
	}
}

static std::string IntToHex(const boost::uint32_t & i, const int & digits) {
	std::ostringstream oss;
	oss << std::hex << std::uppercase << std::setfill('0') << std::setw(digits) << i;
	return oss.str();
}

static void print_entry(util::ofstream & ofs, const setup::info & info,
                        size_t i, const setup::registry_entry & entry) {
	(void)i;
	
    StrParam(ofs, "Root", RegRootToStr(entry), false);
    StrParam(ofs, "Subkey", entry.key);
    StrParam(ofs, "ValueName", entry.name);

	std::string vType = "";
	std::string t = "";
	if (entry.type != setup::registry_entry::None) {
		switch(entry.type) {
			case setup::registry_entry::String:
				vType = "String";
				t.assign(entry.value);
				util::to_utf8(t, info.codepage, &info.header.lead_bytes);
				break;
			case setup::registry_entry::ExpandString:
				vType = "ExpandSZ";
				// TODO: Find an example to make sure this is the expected value
				t.assign(entry.value);
				util::to_utf8(t, info.codepage, &info.header.lead_bytes);
				break;
			case setup::registry_entry::DWord:
				vType = "Dword";
				if (info.version >= INNO_VERSION_EXT(4, 1, 0, 4)) {
					t = entry.value;
				} else {
					// TODO: Convert to this instead of the t=entry.value:
					// Find an example to assist with the change
					//Move(ValueData[1],i,4); t:=Format('$%x', [i]);
					t = entry.value;
				}
				break;
			case setup::registry_entry::Binary:
				vType = "Binary";
				// TODO: Find an example to make sure this is the expected value
				std::ostringstream oss;
				for(size_t i=0; i < entry.value.length(); i++) {
					oss << IntToHex(entry.value[i], 2) << ' ';
				}
				t = oss.str();
				if (t.length() > 0) {
					t = t.substr(0, t.length()-1);
				}
				break;
			case setup::registry_entry::MultiString:
				vType = "MultiSZ";
				t = entry.value;
				std::regex null_re("\\0");
				// The original code at https://github.com/WhatTheBlock/innounp/blob/main/src/RebuildScript.pas#L563
				// seem to add the `break}` to the s variable instead of the t one, which is probably a typo.
				// TODO: Find an example to make sure this is the expected value
				t = std::regex_replace(t, null_re, "{break}");
				break;
			case setup::registry_entry::QWord:
				vType = "Qword";
				t = entry.value;
				break;
			default:
				vType = "Unknown";
				break;
		}
	}

    StrParam(ofs, "ValueType", vType, false);
    StrParam(ofs, "ValueData", t);
	
	PrintItem(ofs, entry);

	std::ostringstream oss;
	if(entry.options) {
		for(size_t o_i = 0; o_i < setup::registry_entry::flags::bits; o_i++) {
			if(entry.options & setup::registry_entry::flags::enum_type(o_i)) {
				std::string o_s = RegistryOpt2Str(setup::registry_entry::flags::enum_type(o_i));
				if (o_s != ""){
					oss << o_s << ' ';
				}
			}
		}
	}
	std::string s = oss.str();
	if (s != "") {
		ofs << "Flags: " << s;
	}
	ofs << '\n';
}

static std::string IniOpt2Str(const setup::ini_entry::flags::enum_type & option) {
	switch(option) {
		case setup::ini_entry::CreateKeyIfDoesntExist:
			return "createkeyifdoesntexist";
		case setup::ini_entry::UninsDeleteEntry:
			return "uninsdeleteentry";
		case setup::ini_entry::UninsDeleteEntireSection:
			return "uninsdeletesection";
		case setup::ini_entry::UninsDeleteSectionIfEmpty:
			return "uninsdeletesectionifempty";
		case setup::ini_entry::HasValue:
		default:
			return "";
	}
}

static void print_entry(util::ofstream & ofs, const setup::info & info,
                        size_t i, const setup::ini_entry & entry) {
	(void)info, (void)i;

    StrParam(ofs, "FileName", entry.inifile);
    StrParam(ofs, "Section", entry.section);
    StrParam(ofs, "Key", entry.key);
    StrParam(ofs, "String", entry.value);

	std::ostringstream oss;
	if(entry.options) {
		for(size_t o_i = 0; o_i < setup::ini_entry::flags::bits; o_i++) {
			if(entry.options & setup::ini_entry::flags::enum_type(o_i)) {
				std::string o_s = IniOpt2Str(setup::ini_entry::flags::enum_type(o_i));
				if (o_s != ""){
					oss << o_s << ' ';
				}
			}
		}
	}
	std::string s = oss.str();
	if (s != "") {
		ofs << "Flags: " << s;
	}
	ofs << '\n';
}

static std::string RunOpt2Str(const setup::run_entry::flags::enum_type & option) {
	switch(option) {
		case setup::run_entry::ShellExec:
			return "shellexec";
		case setup::run_entry::SkipIfDoesntExist:
			return "skipifdoesntexist";
		case setup::run_entry::PostInstall:
			return "postinstall";
		case setup::run_entry::Unchecked:
			return "unchecked";
		case setup::run_entry::SkipIfSilent:
			return "skipifsilent";
		case setup::run_entry::SkipIfNotSilent:
			return "skipifnotsilent";
		case setup::run_entry::HideWizard:
			return "hidewizard";
		case setup::run_entry::Bits32:
			return "32bit";
		case setup::run_entry::Bits64:
			return "64bit";
		case setup::run_entry::RunAsOriginalUser:
		case setup::run_entry::DontLogParameters:
		case setup::run_entry::LogOutput:
		default:
			break;
	}

	return "";
}

static void print_entry(util::ofstream & ofs, const setup::info & info,
                        size_t i, const setup::run_entry & entry) {
	(void)info, (void)i;

    StrParam(ofs, "Filename", entry.name);
    StrParam(ofs, "Parameters", entry.parameters);
    StrParam(ofs, "WorkingDir", entry.working_dir);
    StrParam(ofs, "RunOnceId", entry.run_once_id);
    StrParam(ofs, "StatusMsg", entry.status_message);
	StrParam(ofs, "Description", entry.description);
	PrintItem(ofs, entry);
	
	std::ostringstream oss;
	
	if(entry.options) {
		for(size_t o_i = 0; o_i < setup::run_entry::flags::bits; o_i++) {
			if(entry.options & setup::run_entry::flags::enum_type(o_i)) {
				std::string o_s = RunOpt2Str(setup::run_entry::flags::enum_type(o_i));
				if (o_s != ""){
					oss << o_s << ' ';
				}
			}
		}
	}
	switch(entry.wait) {
		case setup::run_entry::NoWait:
			oss << "nowait";
			break;
		case setup::run_entry::WaitUntilIdle:
			oss << "waituntilidle";
			break;
		default:
			break;
	}
	std::string s = oss.str();
	if (s != "") {
		ofs << "Flags: " << s;
	}
	ofs << '\n';
}

static void print_entry(util::ofstream & ofs, const setup::info & info,
                        size_t i, const setup::icon_entry & entry) {
	(void)info, (void)i;

    StrParam(ofs, "Name", entry.name);
    StrParam(ofs, "Filename", entry.filename);
    StrParam(ofs, "Parameters", entry.parameters);
	StrParam(ofs, "WorkingDir", entry.working_dir);
	StrParam(ofs, "IconFilename", entry.icon_file);
    IntParam(ofs, "IconIndex", entry.icon_index, false);
	StrParam(ofs, "Comment", entry.comment);
	PrintItem(ofs, entry);

	std::ostringstream oss;
	switch(entry.close_on_exit) {
		case setup::icon_entry::CloseOnExit:
			oss << "closeonexit ";
			break;
		case setup::icon_entry::DontCloseOnExit:
			oss << "dontcloseonexit ";
			break;
		default:
			break;
	}
	switch(entry.show_command) {
		// Converted to int using https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow
		case 3: //SW_SHOWMAXIMIZED
			oss << "runmaximized ";
			break;
		case 7: //SW_SHOWMINNOACTIVE
			oss << "runminimized ";
			break;
		default:
			break;
	}
	std::string s = oss.str();
	if (s != "") {
		ofs << "Flags: " << s;
	}
	ofs << '\n';
}

static void print_entry(util::ofstream & ofs, const setup::info & info,
                        size_t i, const setup::task_entry & entry) {
	(void)info, (void)i;

    StrParam(ofs, "Name", entry.name);
    StrParam(ofs, "Description", entry.description);
    StrParam(ofs, "GroupDescription", entry.group_description);
	StrParam(ofs, "Components", entry.components);
	StrParam(ofs, "Languages", entry.languages);
	StrParam(ofs, "Check", entry.check);

	PrintVersions(ofs, entry.winver);

	ofs << '\n';
}

static void print_entry(util::ofstream & ofs, const setup::info & info,
                        size_t i, const setup::component_entry & entry) {
	(void)info, (void)i;

    StrParam(ofs, "Name", entry.name);
    StrParam(ofs, "Description", entry.description);
    StrParam(ofs, "Types", boost::replace_all_copy(entry.types, ",", " "));
    IntParam(ofs, "ExtraDiskSpaceRequired", entry.extra_disk_pace_required);
    StrParam(ofs, "Languages", entry.languages);
    StrParam(ofs, "Check", entry.check);
	
	PrintVersions(ofs, entry.winver);
	ofs << '\n';
}
		
static std::string DeleteType2Str(const setup::delete_entry::target_type & type) {
	switch(type) {
		case setup::delete_entry::Files:
			return "files";
		case setup::delete_entry::FilesAndSubdirs:
			return "filesandordirs";
		case setup::delete_entry::DirIfEmpty:
			return "dirifempty";
		default:
			return "";
	}
}

static void print_entry(util::ofstream & ofs, const setup::info & info,
                        size_t i, const setup::delete_entry & entry) {
	(void)info, (void)i;

    StrParam(ofs, "Type", DeleteType2Str(entry.type), false);
    StrParam(ofs, "Name", entry.name);
	PrintItem(ofs, entry, false, false);
	ofs << '\n';
}

static void print_entry(util::ofstream & ofs, const setup::info & info,
                        size_t i, const setup::type_entry & entry) {
	(void)info, (void)i;

    StrParam(ofs, "Name", entry.name);
    StrParam(ofs, "Description", entry.description);
    StrParam(ofs, "Languages", entry.languages);
    StrParam(ofs, "Check", entry.check);

	PrintVersions(ofs, entry.winver);
	ofs << '\n';
}

static void print_entry(util::ofstream & ofs, const setup::info & info,
                        size_t i, const setup::message_entry & entry) {
	(void)i;

	std::ostringstream oss;

	if(entry.language >= 0) {
		oss << info.languages[size_t(entry.language)].name << '.';
	}
	oss << entry.name;

	ofs << StrConst(oss.str(), boost::replace_all_copy(entry.value, "\x0d\x0a", "%n"));
}

static void print_entry(util::ofstream & ofs, const setup::info & info,
                        size_t i, const setup::language_entry & entry) {
	(void)info, (void)i;
	
    StrParam(ofs, "Name", entry.name);
    StrParam(ofs, "MessagesFile", "embedded\\"+entry.name+".isl");
	if (entry.license_text != "") {
		StrParam(ofs, "LicenseFile", MaybeToRtf("embedded\\"+entry.name+"License.txt", entry.license_text));
	}
	if (entry.info_before != "") {
		StrParam(ofs, "InfoBeforeFile", MaybeToRtf("embedded\\"+entry.name+"InfoBefore.txt", entry.info_before));
	}
	if (entry.info_after != "") {
		StrParam(ofs, "InfoAfterFile", MaybeToRtf("embedded\\"+entry.name+"InfoAfter.txt", entry.info_after));
	}
  	ofs << '\n';

}

template <class Entry>
static void print_entries(util::ofstream & ofs, const setup::info & info, 
						  const std::vector<Entry> & entries, const std::string & name) {
	if(entries.empty()) {
		return;
	}
	
	ofs << SectionHeader(name);
	for(size_t i = 0; i < entries.size(); i++) {
		print_entry(ofs, info, i, entries[i]);
	}
}

// Special one to print comment for languages
static void print_entries(util::ofstream & ofs, const setup::info & info, 
						  const std::vector<setup::language_entry> & entries, const std::string & name) {
	if(entries.empty()) {
		return;
	}
	
	ofs << SectionHeader(name);
	ofs << "; These files are stubs\n";
	ofs << "; To achieve better results after recompilation, use the real language files\n";
	for(size_t i = 0; i < entries.size(); i++) {
		print_entry(ofs, info, i, entries[i]);
	}
}

static std::string UnUnicode(const std::string & s) {
	return s;
	//TODO: Find an example to assist with the change
	/*
	function UnUnicode(s: AnsiString) : AnsiString;
	var
	i,n:integer;
	begin
	i:=1; Result:='';
	while i<=length(s) do begin
		if Ver>=4202 then n:=(byte(s[i+1]) shl 8) or byte(s[i])
		else n:=byte(s[i]);//(byte(s[i]) shl 8) or byte(s[i+1]);
		if (n>=32) and (n<=127) then Result:=Result+char(n)
		else Result:=Result+'<'+{IntToStr(n)} Format('%4.4x', [n])+'>';
		if Ver>=4202 then inc(i,2) else inc(i);
	end;
	end;
	*/
}

static void open_file(util::ofstream & ofs, const fs::path & path) {
	try {
		ofs.open(path, std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);
		if(!ofs.is_open()) {
			throw std::exception();
		}
	} catch(...) {
		throw std::runtime_error("Could not open output file \"" + path.string() + '"');
	}
}

static void add_embedded_files(const boost::filesystem::path & o, const setup::info & info) {
	util::ofstream ofs;
	if (info.header.license_text != "") {
		std::string name = MaybeToRtf("License", info.header.license_text);
		open_file(ofs, o / "embedded" / name);
		ofs << info.header.license_text;
		ofs.close();
		std::cout << " - " << '"' << color::white << "embedded/" << name << color::reset << '"' << '\n';
	}
	if (info.header.info_before != "") {
		std::string name = MaybeToRtf("InfoBefore", info.header.info_before);
		open_file(ofs, o / "embedded" / name);
		ofs << info.header.info_before;
		ofs.close();
		std::cout << " - " << '"' << color::white << "embedded/" << name << color::reset << '"' << '\n';
	}
	if (info.header.info_after != "") {
		std::string name = MaybeToRtf("InfoAfter", info.header.info_after);
		open_file(ofs, o / "embedded" / name);
		ofs << info.header.info_after;
		ofs.close();
		std::cout << " - " << '"' << color::white << "embedded/" << name << color::reset << '"' << '\n';
	}

	if (!info.wizard_images.empty()) {
		for(size_t i = 0; i < info.wizard_images.size(); i++) {
			std::string name = GetWizardImageFileName(i, false);
			open_file(ofs, o / "embedded" / name);
			ofs << info.wizard_images[i];
			ofs.close();
			std::cout << " - " << '"' << color::white << "embedded/" << name << color::reset << '"' << '\n';
		}
	}
	if (!info.wizard_images_small.empty()) {
		for(size_t i = 0; i < info.wizard_images.size(); i++) {
			std::string name = GetWizardImageFileName(i, true);
			open_file(ofs, o / "embedded" / name);
			ofs << info.wizard_images_small[i];
			ofs.close();
			std::cout << " - " << '"' << color::white << "embedded/" << name << color::reset << '"' << '\n';
		}
	}
	
	if (info.decompressor_dll != "") {
		open_file(ofs, o / "embedded" / "decompressor.dll");
		ofs << info.decompressor_dll;
		ofs.close();
		std::cout << " - " << '"' << color::white << "embedded/" << "decompressor.dll" << color::reset << '"' << '\n';
	}
	
	if (info.header.info_after != "") {
		open_file(ofs, o / "embedded" / "decrypt.dll");
		ofs << info.decrypt_dll;
		ofs.close();
		std::cout << " - " << '"' << color::white << "embedded/" << "decrypt.dll" << color::reset << '"' << '\n';
	}

	for (size_t i = 0; i < info.languages.size(); i++) {
		const setup::language_entry & entry = info.languages[i];
		open_file(ofs, o / "embedded" / (entry.name+".isl"));
		ofs << SectionHeader("LangOptions", false);
		ofs << StrConst("LanguageName", UnUnicode(entry.language_name));
		ofs << StrConst("LanguageID", '$' + IntToHex(entry.language_id, 4));
		// https://github.com/WhatTheBlock/innounp/blob/main/src/StructTemplate.pas#L1099 zero'd in certain conditions
		if (info.version < INNO_VERSION_EXT(4, 2, 0, 2) || info.version.is_unicode()) {
			ofs << StrConst("LanguageCodePage", "0");
		} else {
			ofs << StrConst("LanguageCodePage", boost::lexical_cast<std::string>(entry.codepage));
		}
		ofs << StrConst("DialogFontName", entry.dialog_font);
		ofs << StrConst("TitleFontName", entry.title_font);
		ofs << StrConst("WelcomeFontName", entry.welcome_font);
		ofs << StrConst("CopyrightFontName", entry.copyright_font);
		ofs << StrConst("DialogFontSize", boost::lexical_cast<std::string>(entry.dialog_font_size));
		ofs << StrConst("TitleFontSize", boost::lexical_cast<std::string>(entry.title_font_size));
		ofs << StrConst("WelcomeFontSize", boost::lexical_cast<std::string>(entry.welcome_font_size));
		ofs << StrConst("CopyrightFontSize", boost::lexical_cast<std::string>(entry.copyright_font_size));
    	if (entry.right_to_left) {
			ofs << StrConst("RightToLeft", "yes");
		}
		ofs.close();
		std::cout << " - " << '"' << color::white << "embedded/" << entry.name << ".isl" << color::reset << '"' << '\n';

		if (entry.license_text != "") {
			open_file(ofs, o / "embedded" / (entry.name+"License.txt"));
			ofs << entry.license_text;
			ofs.close();
			std::cout << " - " << '"' << color::white << "embedded/" << entry.name << "License.txt" << color::reset << '"' << '\n';
		}
		if (entry.info_before != "") {
			open_file(ofs, o / "embedded" / (entry.name+"InfoBefore.txt"));
			ofs << entry.info_before;
			ofs.close();
			std::cout << " - " << '"' << color::white << "embedded/" << entry.name << "InfoBefore.txt" << color::reset << '"' << '\n';
		}
		if (entry.info_after != "") {
			open_file(ofs, o / "embedded" / (entry.name+"InfoAfter.txt"));
			ofs << entry.info_after;
			ofs.close();
			std::cout << " - " << '"' << color::white << "embedded/" << entry.name << "InfoAfter.txt" << color::reset << '"' << '\n';
		}
	}
}

void dump_iss(const setup::info & info, const extract_options & o, const fs::path & installer) {
	fs::path path = o.output_dir / "install_script.iss";
	util::ofstream ofs;
	open_file(ofs, path);
	
	try {
		ofs << std::boolalpha;

		// Add UTF-8 BOM to script start for Unicode versions.
		if (info.listed_version.is_unicode()){
			ofs << "\xEF\xBB\xBF";
		}
		
		print_header(ofs, info, installer);

		print_entries(ofs, info, info.files, "Files");
		print_entries(ofs, info, info.directories, "Dirs");
		print_entries(ofs, info, info.registry_entries, "Registry");
		print_entries(ofs, info, info.ini_entries, "INI");
		print_entries(ofs, info, info.run_entries, "Run");
		print_entries(ofs, info, info.uninstall_run_entries, "UninstallRun");
		print_entries(ofs, info, info.icons, "Icons");
		print_entries(ofs, info, info.tasks, "Tasks");
		print_entries(ofs, info, info.components, "Components");
		print_entries(ofs, info, info.delete_entries, "InstallDelete");
		print_entries(ofs, info, info.uninstall_delete_entries, "UninstallDelete");
		print_entries(ofs, info, info.types, "Types");
		print_entries(ofs, info, info.messages, "CustomMessages");
		print_entries(ofs, info, info.languages, "Languages");
		ofs.close();
		add_embedded_files(o.output_dir, info);
	} catch(const std::exception & e) {
		std::ostringstream oss;
		oss << "Stream error while dumping iss file!\n";
		oss << " └─ error reason: " << e.what();
		throw format_error(oss.str());
	}
}

} // namespace iss
