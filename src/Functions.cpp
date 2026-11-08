#include "Functions.h"
#include "InvincibleFrames.h"
#include <cmath>

namespace MaxsuIFrame
{
	static inline RE::hkbClipGenerator* ToClipGenerator(RE::hkbNode* a_node)
	{
		const auto type = a_node ? a_node->GetClassType() : nullptr;
		if (type && type->name && std::strcmp(type->name, "hkbClipGenerator") == 0) {
			return static_cast<RE::hkbClipGenerator*>(a_node);
		}

		return nullptr;
	}

	static bool ClipInIFrames(const RE::hkbClipGenerator* a_clip, bool& a_invalidAnnotation)
	{
		if (!a_clip || !std::isfinite(a_clip->localTime))
			return false;

		auto binding = a_clip->binding;
		auto animation = binding ? binding->animation : nullptr;

		if (!animation || animation->annotationTracks.empty())
			return false;

		thread_local AnnotationCache cache;
		const float localTime = a_clip->localTime;
		for (const auto& anno : animation->annotationTracks[0].annotations) {
			if (!std::isfinite(anno.time) || localTime < anno.time) {
				continue;
			}
			const auto payload = GetInvincibilityPayload(anno.text.c_str());
			if (!payload) {
				continue;
			}
			const auto result = cache.Get(*payload);
			a_invalidAnnotation = a_invalidAnnotation || result.newlyInvalid;
			if (result.frames && result.frames->IsInFrames(anno.time, localTime)) {
				return true;
			}
		}

		return false;
	}

	bool ActorInIFrames(const RE::Actor* a_actor)
	{
		if (!a_actor || !a_actor->Is3DLoaded()) {
			return false;
		}
		RE::BSAnimationGraphManagerPtr graphMgr;
		if (!a_actor->GetAnimationGraphManager(graphMgr) || !graphMgr) {
			return false;
		}

		bool inFrames = false;
		bool invalidAnnotation = false;
		{
			RE::BSSpinLockGuard guard(graphMgr->GetRuntimeData().updateLock);
			const auto graph = !graphMgr->graphs.empty() ? graphMgr->graphs[0] : RE::BShkbAnimationGraphPtr{};
			const auto behavior = graph ? graph->behaviorGraph : nullptr;
			const auto nodes = behavior ? behavior->activeNodes : nullptr;
			if (nodes) {
				for (const auto& node : *nodes) {
					if (const auto clip = ToClipGenerator(node.nodeClone); clip && ClipInIFrames(clip, invalidAnnotation)) {
						inFrames = true;
						break;
					}
				}
			}
		}
		if (invalidAnnotation) {
			SKSE::log::warn("Ignored malformed invincibility annotation");
		}
		return inFrames;
	}

}
