# SANSAR artifact review

The default scan checks a small set of locations from [Elastic Security Labs](https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware), published November 12, 2026. The observed intrusion occurred October 22–25. Source checked November 17.

It checks `/opt/vadi_` and selected toolkit filenames, the NVML wrapper at `/opt/vadi_/nvml-hook/libnvidia-ml.so.1`, `acpi_thermal_mgr` under `/sys/module` and `/var/lib/dkms`, selected initramfs/modules-load configuration, and `netns.service` launching `/opt/vadi_/netns` under `/etc/systemd/system` or `/usr/lib/systemd/system`.

A single artifact is a review lead. Multiple artifact categories increase priority to warning, without establishing execution, attribution, or compromise. Generic `netns` paths, ordinary NVIDIA libraries, legitimate miners elsewhere and zero-percent GPU readings are not campaign verdicts.

Inspection uses bounded, descriptor-anchored reads. Discovered symlinks are not followed. Unreadable, excluded, oversized or limited inspection makes coverage incomplete. Results contain structural paths, never configuration contents. No target code runs, no network requests occur, and no remediation is performed.

This does not inspect RAM, compressed boot images, arbitrary library binaries, alternate staging locations, network reachability or Ray authentication. A negative result cannot clear a host, especially when a rootkit may hide files. Verify suspicious artifacts and package integrity from a trusted environment. Review the Ray job agent separately from the dashboard: Elastic observed an exposed agent even though the dashboard listened on loopback.
