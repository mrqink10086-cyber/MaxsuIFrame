#include "InvincibleFrames.h"

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <thread>
#include <nlohmann/json.hpp>

namespace
{
	void Check(bool a_condition, const char* a_message)
	{
		if (!a_condition) {
			std::cerr << "FAIL: " << a_message << '\n';
			std::exit(1);
		}
	}

	void CheckFrames()
	{
		Check(!MaxsuIFrame::GetInvincibilityPayload(nullptr), "null annotation text");
		Check(!MaxsuIFrame::GetInvincibilityPayload(""), "empty annotation text");
		Check(!MaxsuIFrame::GetInvincibilityPayload("SpecialFrames_"), "short prefix");
		Check(!MaxsuIFrame::GetInvincibilityPayload("ordinary event"), "unrelated annotation");
		Check(MaxsuIFrame::GetInvincibilityPayload("SpecialFrames_Invincible{\"Duration\":0.5}") ==
			std::optional<std::string_view>{ R"({"Duration":0.5})" }, "annotation payload");
		const auto atLimit = std::string("SpecialFrames_Invincible") + std::string(MaxsuIFrame::AnnotationCache::MaxTextBytes, ' ');
		Check(MaxsuIFrame::GetInvincibilityPayload(atLimit.c_str())->size() == MaxsuIFrame::AnnotationCache::MaxTextBytes, "bounded payload at limit");
		const auto overLimit = atLimit + " ";
		Check(!MaxsuIFrame::GetInvincibilityPayload(overLimit.c_str()), "bounded payload over limit");
		MaxsuIFrame::AnnotationCache cache;
		const auto frames = cache.Get(R"({"Duration":0.5})").frames;
		Check(frames.has_value(), "valid duration");
		Check(frames->IsInFrames(0.1F, 0.1F), "inclusive start");
		Check(frames->IsInFrames(0.1F, 0.6F), "inclusive end");
		Check(!frames->IsInFrames(0.1F, 0.099F), "before window");
		Check(!frames->IsInFrames(0.1F, 0.601F), "after window");
		Check(!frames->IsInFrames(0.1F, std::numeric_limits<float>::quiet_NaN()), "NaN time");
		Check(!frames->IsInFrames(std::numeric_limits<float>::infinity(), 1.0F), "infinite start");
		Check(!MaxsuIFrame::InvincibleFrames{ std::numeric_limits<float>::max() }.IsInFrames(
			std::numeric_limits<float>::max(), std::numeric_limits<float>::max()), "overflowing end");
		const auto negative = cache.Get(R"({"Duration":-1})").frames;
		Check(negative && negative->duration == 0.0F, "negative duration clamps to zero");
		Check(negative->IsInFrames(1.0F, 1.0F) && !negative->IsInFrames(1.0F, 1.001F), "zero window");
		for (const auto text : { "", "{", "[]", "null", "{}", R"({"Duration":"0.5"})",
			R"({"Duration":true})", R"({"Duration":1e100})", R"({"Duration":1e999})" }) {
			const auto first = cache.Get(text);
			Check(!first.frames && first.newlyInvalid, "invalid annotation rejected on first parse");
			const auto again = cache.Get(text);
			Check(!again.frames && !again.newlyInvalid, "invalid result cached");
		}
		const auto nested = std::string("{\"Duration\":0.5,\"extra\":") + std::string(32, '[') + "0" + std::string(32, ']') + "}";
		Check(!cache.Get(nested).frames, "deep nesting rejected");
		Check(!cache.Get(std::string(MaxsuIFrame::AnnotationCache::MaxTextBytes + 1, ' ')).frames, "oversized JSON rejected");
		std::string owned = R"({"Duration":0.25})";
		Check(cache.Get(owned).frames->duration == 0.25F, "initial owned content");
		owned = R"({"Duration":0.75})";
		Check(cache.Get(owned).frames->duration == 0.75F, "changed source content");
		Check(cache.Get(R"({"Duration":0.25})").frames->duration == 0.25F, "cache owns its key");
		for (std::size_t i = 0; i < MaxsuIFrame::AnnotationCache::MaxEntries * 3; ++i) {
			const auto result = cache.Get("{\"Duration\":" + std::to_string(i) + "}");
			Check(result.frames && result.frames->duration == static_cast<float>(i), "cache churn result");
			Check(cache.Size() <= MaxsuIFrame::AnnotationCache::MaxEntries, "bounded cache entries");
		}
	}

	void CheckThreads()
	{
		std::atomic<bool> correct{ true };
		std::vector<std::thread> workers;
		for (int worker = 0; worker < 8; ++worker) {
			workers.emplace_back([worker, &correct] {
				thread_local MaxsuIFrame::AnnotationCache cache;
				const auto text = "{\"Duration\":" + std::to_string(worker) + "}";
				for (int i = 0; i < 10000; ++i) {
					const auto result = cache.Get(text);
					if (!result.frames || result.frames->duration != static_cast<float>(worker)) {
						correct = false;
					}
				}
			});
		}
		for (auto& worker : workers) {
			worker.join();
		}
		Check(correct, "independent per-thread cache results");
	}

	void Benchmark()
	{
		constexpr std::string_view text = R"({"Duration":0.5})";
		constexpr int iterations = 200000;
		MaxsuIFrame::AnnotationCache cache;
		cache.Get(text);
		float sum = 0.0F;
		const auto start = std::chrono::steady_clock::now();
		for (int i = 0; i < iterations; ++i) {
			sum += nlohmann::json::parse(text).at("Duration").get<float>();
		}
		const auto baselineEnd = std::chrono::steady_clock::now();
		for (int i = 0; i < iterations; ++i) {
			sum += cache.Get(text).frames->duration;
		}
		const auto cachedEnd = std::chrono::steady_clock::now();
		const auto baseline = std::chrono::duration<double, std::nano>(baselineEnd - start).count() / iterations;
		const auto cached = std::chrono::duration<double, std::nano>(cachedEnd - baselineEnd).count() / iterations;
		std::cout << "Duration lookup microbenchmark: JSON=" << baseline << " ns, warm cache=" << cached
		          << " ns, ratio=" << baseline / cached << ", checksum=" << sum << '\n';
	}
}

int main()
{
	CheckFrames();
	CheckThreads();
	Benchmark();
	std::cout << "All frame/cache tests passed\n";
}
