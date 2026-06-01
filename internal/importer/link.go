package importer

import (
	"os"

	plerrors "github.com/MasuRii/PureLink/pkg/errors"
	"github.com/MasuRii/PureLink/pkg/v2rayn"
)

func ImportLinkFile(path string) ([]v2rayn.ImportedEndpoint, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- CLI import intentionally reads user-specified link files.
	if err != nil {
		if os.IsNotExist(err) {
			return nil, plerrors.ErrFileNotFound
		}
		return nil, err
	}
	return DeduplicateImported(v2rayn.ParseContent(string(b))), nil
}
