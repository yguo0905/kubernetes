/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package system

import (
	"fmt"
	"os/exec"
	"strings"

	"k8s.io/apimachinery/pkg/util/errors"

	"github.com/blang/semver"
	"github.com/golang/glog"
)

var _ Validator = &packageValidator{}

const semVerDotsCount int = 2

// packageManager is an interface that abstracts basic operations of a package
// manager for retrieving versions of packages installed on running machine.
type packageManager interface {
	getPackageVersion(packageName string) (string, error)
}

// newPackageManager returns the package manager on the running machine, and an
// error if no package managers is available.
func newPackageManager() (packageManager, error) {
	if m, ok := newDPKG(); ok {
		return m, nil
	}
	return nil, fmt.Errorf("failed to find package manager")
}

// dpkg implements packageManager. It uses "dpkg-query" to retrieve package
// information.
type dpkg struct{}

// newDPKG returns a Debian package manager. It returns (nil, false) if no such
// package manager exists on the running machine.
func newDPKG() (packageManager, bool) {
	_, err := exec.LookPath("dpkg-query")
	if err != nil {
		return nil, false
	}
	return dpkg{}, true
}

// getPackageVersion returns the upstream package version for the package with
// the packageName, and an error if not such package exists.
func (_ dpkg) getPackageVersion(packageName string) (string, error) {
	cmd := exec.Command("dpkg-query", "--show", "--showformat='${Version}'", packageName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get version of package %q: %s", packageName, err)
	}
	version := extractUpstreamVersion(string(output))
	if version == "" {
		return "", fmt.Errorf("failed to get version of package %q", packageName)
	}
	return version, nil
}

// packageValidator implements Validator. It validates package versions.
type packageValidator struct {
	Reporter Reporter
}

func (pv *packageValidator) Name() string {
	return "package"
}

func (pv *packageValidator) Validate(spec SysSpec) (error, error) {
	if len(spec.PackageSpecs) == 0 {
		return nil, nil
	}
	manager, err := newPackageManager()
	if err != nil {
		return nil, err
	}
	return pv.validate(spec, manager)
}

func (pv *packageValidator) validate(spec SysSpec, manager packageManager) (error, error) {
	var errs []error
	for _, spec := range spec.PackageSpecs {
		// Get the version of the package on running machine.
		version, err := manager.getPackageVersion(spec.Name)
		if err != nil {
			glog.V(1).Infof("%s\n", err)
			glog.Errorf("%s\n", err)
			errs = append(errs, err)
			pv.report(spec.Name, spec.VersionRange, "not installed", bad)
			continue
		}

		// Version requirement will not be enforced if version range is
		// not specified in the spec.
		if spec.VersionRange == "" {
			continue
		}

		// Convert both the version range in the spec and the version returned
		// from package manager to semantic version, and make the verification.
		sv, err := semver.Make(toSemVer(version))
		if err != nil {
			glog.Errorf("%s\n", err)
			errs = append(errs, err)
			pv.report(spec.Name, spec.VersionRange, "internal error", bad)
			continue
		}
		versionRange := semver.MustParseRange(toSemVerRange(spec.VersionRange))
		if versionRange(sv) {
			pv.report(spec.Name, spec.VersionRange, version, good)
		} else {
			err := fmt.Errorf("package \"%s %s\" does not meet the spec \"%s (%s)\"", spec.Name, sv, spec.Name, spec.VersionRange)
			errs = append(errs, err)
			pv.report(spec.Name, spec.VersionRange, version, bad)
		}
	}
	return nil, errors.NewAggregate(errs)
}

func (pv *packageValidator) report(packageName, versionRange, status string, result ValidationResultType) {
	if versionRange == "" {
		pv.Reporter.Report(packageName, status, result)
		return
	}
	pv.Reporter.Report(fmt.Sprintf("%s (%s)", packageName, versionRange), status, result)
}

// extractUpstreamVersion returns the upstream version of the given full
// version in dpkg format. E.g., "1:1.0.6-2ubuntu2.1" -> "1.0.6".
func extractUpstreamVersion(version string) string {
	// The full version is in the format of
	// "[epoch:]upstream_version[-debian_revision]". See
	// https://www.debian.org/doc/debian-policy/ch-controlfields.html#s-f-Version.
	version = strings.Trim(version, " '")
	if i := strings.Index(version, ":"); i != -1 {
		version = version[i+1:]
	}
	if i := strings.Index(version, "-"); i != -1 {
		version = version[:i]
	}
	return version
}

// toSemVerRange converts the input to a semantic version range.
// E.g., ">=1.0"             -> ">=1.0.x"
//       ">=1"               -> ">=1.x"
//       ">=1 <=2.3"         -> ">=1.x <=2.3.x"
//       ">1 || >3.1.0 !4.2" -> ">1.x || >3.1.0 !4.2.x"
func toSemVerRange(input string) string {
	var output []string
	fields := strings.Fields(input)
	for _, f := range fields {
		numDots, hasDigits := 0, false
		for _, c := range f {
			switch {
			case c == '.':
				numDots++
			case c >= '0' && c <= '9':
				hasDigits = true
			}
		}
		if hasDigits && numDots < semVerDotsCount {
			f = strings.TrimRight(f, " ")
			f += ".x"
		}
		output = append(output, f)
	}
	return strings.Join(output, " ")
}

// toSemVer converts the input to a semantic version, and an empty string on
// error.
func toSemVer(version string) string {
	// Remove the first non-digit and non-dot character as well as the ones
	// following it.
	// E.g., "1.8.19p1" -> "1.8.19".
	if i := strings.IndexFunc(version, func(c rune) bool {
		if (c < '0' || c > '9') && c != '.' {
			return true
		}
		return false
	}); i != -1 {
		version = version[:i]
	}

	// Remove the trailing dots if there's any, and returns an empty string if
	// nothing left.
	version = strings.TrimRight(version, ".")
	if version == "" {
		return ""
	}

	numDots := strings.Count(version, ".")
	switch {
	case numDots < semVerDotsCount:
		// Add minor version and patch version.
		// E.g. "1.18" -> "1.18.0" and "481" -> "481.0.0".
		version += strings.Repeat(".0", semVerDotsCount-numDots)
	case numDots > semVerDotsCount:
		// Remove the parts beyong the patch version
		// E.g. "2.0.10.4" -> "2.0.10".
		for numDots != semVerDotsCount {
			if i := strings.LastIndex(version, "."); i != -1 {
				version = version[:i]
				numDots--
			}
		}
	}

	// Remove leading zeros in patch version.
	// E.g., "8.0.0095" -> "8.0.95".
	if i := strings.LastIndex(version, "."); i != -1 && i < len(version)-2 {
		version = version[:i+1] + strings.TrimLeft(version[i+1:], "0")
	}
	return version
}
