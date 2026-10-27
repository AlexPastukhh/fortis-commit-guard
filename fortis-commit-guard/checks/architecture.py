"""Optional contracts; disabling this module never disables security modules."""


def inspect_test_presence(files, baseline, test_roots, finding):
    for path in sorted(set(baseline) - set(files)):
        if any(path.startswith(root) for root in test_roots):
            finding('test-removed', path, 'Removing ordinary project tests requires architecture review', 'review')
