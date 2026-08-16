    def _run_campaign(self, campaign: Campaign):
    """Execute campaign steps sequentially."""
    self.executor.set_scope_guard(self.scope_guard)

    while True:
        # Get next executable steps
        step_results = {s.id: s.result for s in campaign.steps if s.result}
        next_steps = self._get_executable_steps(campaign, step_results)

        if not next_steps:
            # Check if campaign is complete
            pending = [s for s in campaign.steps if s.state == "pending"]
            if not pending:
                print("[+] Campaign completed!")
                self._show_summary(campaign)
                break
            else:
                # Check if blocked
                blocked = [s for s in campaign.steps if s.state == "blocked"]
                if blocked:
                    print(f"[!] Campaign blocked on {len(blocked)} step(s)")
                    for s in blocked:
                        print(f"    - {s.id}: {s.evidence.get('block_reason', 'unknown')}")
                else:
                    print("[!] No executable steps but campaign not complete")
                break

        # Execute next step(s)
        for step_id in next_steps:
            step = next(s for s in campaign.steps if s.id == step_id)
            print(f"\n[>] Executing step: {step_id} ({step.tool})")
            print(f"    Command: {' '.join(step.render_command(build_context(campaign, {s.id: s.result for s in campaign.steps if s.result})))}")

            if self.dry_run:
                print("    [DRY RUN] Skipping execution")
                continue

            # Execute step
            async def run_step():
                return await self.executor.execute_step(step, self.scope_guard)

            result = asyncio.run(run_step())

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
