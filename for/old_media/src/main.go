package main

import (
	"io"
	"math/rand"
	"os"

	"github.com/tinyrange/tinyrange/v3/experimental/fs/fat"
	"github.com/tinyrange/tinyrange/v3/pkg/common/binary"
	"github.com/tinyrange/tinyrange/v3/pkg/log"
)

type BinaryFile struct {
	writer io.WriterAt
}

func (f *BinaryFile) NewOffsetWriter(offset int64) binary.BinaryWriter {
	return binary.NewWriter(io.NewOffsetWriter(f.writer, offset), binary.LittleEndian)
}

func main() {
	f, err := os.Create("local/fat.bin")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	bf := &BinaryFile{writer: f}

	bios := &fat.BiosParameterBlock{
		Bootjmp:             [3]byte{0xEB, 0x3C, 0x90},
		OemName:             "OCEANDOS",
		BytesPerSector:      512,
		SectorsPerCluster:   1,
		ReservedSectorCount: 1,
		TableCount:          2,
		RootEntryCount:      224,
		TotalSectors16:      2880,
		MediaType:           240,
		TableSize16:         9,
		SectorsPerTrack:     18,
		HeadSideCount:       2,
	}
	ext := &fat.ExtendedBootSectorFat16{
		BiosDriveNum:               0,
		Reserved1:                  0,
		BootSignature:              0x29,
		VolumeId:                   759826699,
		VolumeLabel:                "MSDOS      ",
		FatTypeLabel:               "FAT12   ",
		BootablePartitionSignature: [2]byte{0x55, 0xAA},
	}

	bf.NewOffsetWriter(1440*1024 - 1).Int8(0)

	if err := bios.Encode(bf.NewOffsetWriter(0)); err != nil {
		log.Fatal(err)
	}

	if err := ext.Encode(bf.NewOffsetWriter(bios.Size())); err != nil {
		log.Fatal(err)
	}

	flag := "oiccflag{hope_you_had_fun_with_a_old_school_filesystem}"

	var ents []struct {
		order int
		char  int
	}

	for i, c := range flag {
		ents = append(ents, struct {
			order int
			char  int
		}{
			order: i,
			char:  int(c),
		})
	}

	rand.Shuffle(len(ents), func(i, j int) {
		ents[i], ents[j] = ents[j], ents[i]
	})

	position := int64(bios.FirstRootDirSector() * bios.SectorSize())

	for _, ent := range ents {
		ent := &fat.Entry83format{
			Name:            "FLAG    ",
			Ext:             "TXT",
			FileSize:        uint32(ent.char),
			FirstClusterLow: uint16(ent.order),
		}

		if err := ent.Encode(bf.NewOffsetWriter(position)); err != nil {
			log.Fatal(err)
		}

		position += ent.Size()
	}
}
