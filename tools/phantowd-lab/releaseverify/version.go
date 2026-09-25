// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package releaseverify

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidVersion indicates that a version does not satisfy the release
	// manifest's bounded SemVer 2.0 subset.
	ErrInvalidVersion = errors.New("invalid release version")
	// ErrNotAnUpgrade indicates that a target version is not newer than the
	// currently installed version.
	ErrNotAnUpgrade = errors.New("target is not a monotonic upgrade")
)

type semanticVersion struct {
	major      string
	minor      string
	patch      string
	prerelease []string
}

// CompareVersions compares two v-prefixed SemVer 2.0 versions. It returns -1
// when left precedes right, 0 when equal, and +1 when left follows right.
// Build metadata is not accepted because release manifest schema v1 excludes it.
func CompareVersions(left, right string) (int, error) {
	leftVersion, err := parseVersion(left)
	if err != nil {
		return 0, fmt.Errorf("left version: %w", err)
	}
	rightVersion, err := parseVersion(right)
	if err != nil {
		return 0, fmt.Errorf("right version: %w", err)
	}
	for _, pair := range [][2]string{
		{leftVersion.major, rightVersion.major},
		{leftVersion.minor, rightVersion.minor},
		{leftVersion.patch, rightVersion.patch},
	} {
		if order := compareNumericIdentifiers(pair[0], pair[1]); order != 0 {
			return order, nil
		}
	}
	if len(leftVersion.prerelease) == 0 && len(rightVersion.prerelease) == 0 {
		return 0, nil
	}
	if len(leftVersion.prerelease) == 0 {
		return 1, nil
	}
	if len(rightVersion.prerelease) == 0 {
		return -1, nil
	}
	limit := min(len(leftVersion.prerelease), len(rightVersion.prerelease))
	for index := 0; index < limit; index++ {
		leftIdentifier := leftVersion.prerelease[index]
		rightIdentifier := rightVersion.prerelease[index]
		leftNumeric := isNumericIdentifier(leftIdentifier)
		rightNumeric := isNumericIdentifier(rightIdentifier)
		switch {
		case leftNumeric && rightNumeric:
			if order := compareNumericIdentifiers(leftIdentifier, rightIdentifier); order != 0 {
				return order, nil
			}
		case leftNumeric:
			return -1, nil
		case rightNumeric:
			return 1, nil
		default:
			if leftIdentifier < rightIdentifier {
				return -1, nil
			}
			if leftIdentifier > rightIdentifier {
				return 1, nil
			}
		}
	}
	if len(leftVersion.prerelease) < len(rightVersion.prerelease) {
		return -1, nil
	}
	if len(leftVersion.prerelease) > len(rightVersion.prerelease) {
		return 1, nil
	}
	return 0, nil
}

// CheckMonotonicUpgrade rejects equal versions and downgrades. It is a policy
// primitive for host-side planning only; it does not authorize installation,
// persist anti-rollback state, or implement an emergency downgrade exception.
func CheckMonotonicUpgrade(current, target string) error {
	order, err := CompareVersions(target, current)
	if err != nil {
		return err
	}
	if order <= 0 {
		return ErrNotAnUpgrade
	}
	return nil
}

func parseVersion(value string) (semanticVersion, error) {
	const maxVersionLength = 128
	if len(value) < 6 || len(value) > maxVersionLength || value[0] != 'v' {
		return semanticVersion{}, ErrInvalidVersion
	}
	coreAndPrerelease := value[1:]
	core, prereleaseText, hasPrerelease := strings.Cut(coreAndPrerelease, "-")
	coreParts := strings.Split(core, ".")
	if len(coreParts) != 3 {
		return semanticVersion{}, ErrInvalidVersion
	}
	for _, part := range coreParts {
		if !validNumericIdentifier(part) {
			return semanticVersion{}, ErrInvalidVersion
		}
	}
	version := semanticVersion{major: coreParts[0], minor: coreParts[1], patch: coreParts[2]}
	if !hasPrerelease {
		return version, nil
	}
	if prereleaseText == "" {
		return semanticVersion{}, ErrInvalidVersion
	}
	version.prerelease = strings.Split(prereleaseText, ".")
	for _, identifier := range version.prerelease {
		if !validPrereleaseIdentifier(identifier) {
			return semanticVersion{}, ErrInvalidVersion
		}
	}
	return version, nil
}

func validNumericIdentifier(value string) bool {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validPrereleaseIdentifier(value string) bool {
	if value == "" {
		return false
	}
	if isNumericIdentifier(value) {
		return validNumericIdentifier(value)
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= 'a' && character <= 'z') || character == '-') {
			return false
		}
	}
	return true
}

func isNumericIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func compareNumericIdentifiers(left, right string) int {
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
