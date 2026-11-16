//go:build embed

package utils

import "github.com/cyberspacesec/gxx/pkg/finger"

func GetFingerYaml() ([]*finger.Finger, error) { return GetEmbeddedFingerYaml() }
