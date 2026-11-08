#include "Hooks.h"

SKSEPluginLoad(const SKSE::LoadInterface* a_skse)
{
	if (a_skse->IsEditor() || a_skse->RuntimeVersion() != SKSE::RUNTIME_SSE_1_6_1170 ||
		a_skse->SKSEVersion() < REL::Version{ 2, 2, 6, 0 }.pack()) {
		return false;
	}

	const auto logDirectory = SKSE::log::log_directory();
	if (!logDirectory) {
		return false;
	}
	const auto logPath = *logDirectory / "MaxsuIFrame.log";
	auto sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(logPath.string(), true);
	auto logger = std::make_shared<spdlog::logger>("global log", std::move(sink));
	spdlog::set_default_logger(std::move(logger));
	spdlog::set_level(spdlog::level::info);
	spdlog::flush_on(spdlog::level::info);

	SKSE::Init(a_skse);
	SKSE::log::info("{} v{}; runtime {}; SKSE {}", Plugin::NAME, Plugin::Version.string(),
		a_skse->RuntimeVersion().string(), REL::Version::unpack(a_skse->SKSEVersion()).string());
	return MaxsuIFrame::IsGhostHook::InstallHook();
}
