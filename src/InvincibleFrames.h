#pragma once
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace MaxsuIFrame
{
	struct InvincibleFrames
	{
		float duration{};
		bool IsInFrames(float a_startTime, float a_localTime) const noexcept;
	};

	class AnnotationCache
	{
	public:
		static constexpr std::size_t MaxEntries = 128;
		static constexpr std::size_t MaxTextBytes = 4096;
		struct Result
		{
			std::optional<InvincibleFrames> frames;
			bool newlyInvalid{};
		};
		Result Get(std::string_view a_json);
		std::size_t Size() const noexcept { return _entries.size(); }

	private:
		struct Entry
		{
			std::string text;
			std::optional<InvincibleFrames> frames;
		};
		std::vector<Entry> _entries;
	};

	std::optional<std::string_view> GetInvincibilityPayload(const char* a_text) noexcept;
}
