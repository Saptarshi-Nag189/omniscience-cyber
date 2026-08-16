            # Update campaign
            self._update_step_result(campaign, step_id, result)
            self.store.save(campaign)

            # Show results
            if result.blocked:
                print(f"    [!] BLOCKED: {result.block_reason}")
            elif result.timed_out:
                print(f"    [!] TIMEOUT ({result.duration:.1f}s)")
            elif result.success:
                print(f"    [+] Completed ({result.duration:.1f}s, {len(result.findings)} findings)")
                for f in result.findings[:3]:
                    print(f"      - {f.title} ({f.severity.value})")
                if len(result.findings) > 3:
                    print(f"      ... and {len(result.findings) - 3} more")
            else:
                print(f"    [-] FAILED: {result.errors}")

    def _get_executable_steps(self, campaign: Campaign, step_results: dict) -> List[str]:
    """Get steps that are ready to execute."""
    ready = []
    for step in campaign.steps:
        if step.state != "pending":
            continue

        # Check dependencies
        deps_met = all(step_results.get(dep_id, {}).get("state") == "completed"
                      for dep_id in step.depends_on)
        if not deps_met:
            continue

        # Check condition
        if not self._check_condition(step):
            continue

        ready.append(step.id)
    return ready

    def _check_condition(self, step: CampaignStep) -> bool:
    if not step.condition:
        return True
    # Simple condition evaluation
    # In a full implementation, this would evaluate the condition expression
    return True

    def _update_step_result(self, campaign: Campaign, step_id: str, result):
    for step in campaign.steps:
        if step.id == step_id:
            step.state = "completed" if result.success else "failed"
            step.result = result
            step.completed_at = datetime.utcnow().isoformat()
            break

    # Add findings to campaign
    for finding in result.findings:
        campaign.add_finding(finding)

    campaign.updated_at = datetime.utcnow().isoformat()

    def _show_summary(self, campaign: Campaign):
    stats = self.finding_store.get_stats(campaign.id)
    print(f"\n{'='*60}")
    print(f"CAMPAIGN SUMMARY: {campaign.id}")
    print(f"{'='*60}")
    print(f"Target: {campaign.target}")
    print(f"Total Findings: {stats['total']}")
    for sev, count in stats["by_severity"].items():
        print(f"  {sev.capitalize()}: {count}")
    print(f"\nFindings saved to findings.db")
    print(f"Campaign state saved to campaigns/{campaign.id}.json")
