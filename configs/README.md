# Buildroot configurations

Future configurations belong here as minimal, reproducible defconfigs.

Use one defconfig per supported model and hardware revision when they differ.
Do not make a single image probe several incompatible NAS models during an
update. CI may use a build matrix, but every output must have an unambiguous
model identifier and compatibility metadata.
