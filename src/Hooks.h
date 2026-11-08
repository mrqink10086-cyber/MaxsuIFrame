#pragma once
#include "Functions.h"

namespace MaxsuIFrame
{
	class IsGhostHook
	{
	public:
		static bool InstallHook()
		{
			const std::array sites{
				REL::ID(38627).address() + 0x47,
				REL::ID(37725).address() + 0x22,
				REL::ID(40504).address() + 0x14
			};
			const auto isGhost = REL::ID(37275).address();
			for (const auto site : sites) {
				std::int32_t displacement{};
				std::memcpy(&displacement, reinterpret_cast<const void*>(site + 1), sizeof(displacement));
				if (*reinterpret_cast<const std::uint8_t*>(site) != 0xE8 || site + 5 + displacement != isGhost) {
					SKSE::log::error("IsGhost callsite mismatch at RVA {:#x}; hooks were not installed", site - REL::Module::get().base());
					return false;
				}
			}

			_IsGhost = isGhost;
			SKSE::AllocTrampoline(32);
			auto& trampoline = SKSE::GetTrampoline();
			for (const auto site : sites) {
				trampoline.write_call<5>(site, IsGhost);
			}
			SKSE::log::info("Installed all three IsGhost hooks");
			return true;
		}

	private:
		static bool IsGhost(const RE::Actor* a_actor)
		{
			if (!a_actor) {
				return false;
			}
			try {
				if (ActorInIFrames(a_actor)) {
					return true;
				}
				static const RE::BSFixedString iframeActiveName{ "bIframeActive" };
				static const RE::BSFixedString iframeStateName{ "bInIframe" };
				bool iframeActive = false, iframeState = false;
				if (a_actor->GetGraphVariableBool(iframeActiveName, iframeActive) && iframeActive &&
					a_actor->GetGraphVariableBool(iframeStateName, iframeState) && iframeState) {
					return true;
				}
			} catch (const std::bad_alloc&) {
			}
			return _IsGhost(a_actor);
		}

		static inline REL::Relocation<decltype(IsGhost)> _IsGhost;
	};
}
