#include "InvincibleFrames.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <nlohmann/json.hpp>

namespace MaxsuIFrame
{
	namespace
	{
		std::optional<InvincibleFrames> ParseFrames(std::string_view a_json)
		{
			try {
				const auto limitDepth = [](int a_depth, nlohmann::json::parse_event_t, nlohmann::json&) {
					if (a_depth > 16) {
						throw std::length_error("Invincibility annotation nesting exceeds 16");
					}
					return true;
				};
				const auto value = nlohmann::json::parse(a_json, limitDepth);
				const auto& durationValue = value.at("Duration");
				if (!durationValue.is_number()) {
					return std::nullopt;
				}
				const float duration = durationValue.get<float>();
				if (std::isfinite(duration)) {
					return InvincibleFrames{ std::max(duration, 0.0F) };
				}
			} catch (const nlohmann::json::exception&) {
			} catch (const std::length_error&) {
			}
			return std::nullopt;
		}
	}

	bool InvincibleFrames::IsInFrames(float a_startTime, float a_localTime) const noexcept
	{
		const float endTime = a_startTime + duration;
		return std::isfinite(a_startTime) && std::isfinite(a_localTime) && std::isfinite(endTime) &&
		       a_localTime >= a_startTime && a_localTime <= endTime;
	}

	AnnotationCache::Result AnnotationCache::Get(std::string_view a_json)
	{
		if (a_json.size() > MaxTextBytes) {
			return {};
		}
		auto entry = std::lower_bound(_entries.begin(), _entries.end(), a_json,
			[](const Entry& a_entry, std::string_view a_text) { return a_entry.text < a_text; });
		if (entry != _entries.end() && entry->text == a_json) {
			return { entry->frames, false };
		}
		const auto frames = ParseFrames(a_json);
		if (_entries.size() == MaxEntries) {
			_entries.clear();
			entry = _entries.begin();
		} else if (_entries.capacity() < MaxEntries) {
			const auto index = _entries.empty() ? 0 : entry - _entries.begin();
			_entries.reserve(MaxEntries);
			entry = _entries.begin() + index;
		}
		_entries.insert(entry, Entry{ std::string(a_json), frames });
		return { frames, !frames.has_value() };
	}

	std::optional<std::string_view> GetInvincibilityPayload(const char* a_text) noexcept
	{
		constexpr std::string_view prefix = "SpecialFrames_Invincible";
		if (!a_text) {
			return std::nullopt;
		}
		for (std::size_t i = 0; i < prefix.size(); ++i) {
			if (a_text[i] != prefix[i]) {
				return std::nullopt;
			}
		}
		const auto payload = a_text + prefix.size();
		std::size_t length = 0;
		while (length <= AnnotationCache::MaxTextBytes && payload[length] != '\0') {
			++length;
		}
		if (length > AnnotationCache::MaxTextBytes) {
			return std::nullopt;
		}
		return std::string_view{ payload, length };
	}
}
