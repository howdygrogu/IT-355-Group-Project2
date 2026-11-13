/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: SecureFiles.java
 *
 * Helpers that create owner-only files, temporary files, and folders on Windows, Linux, and macOS.
 */

package securebank;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Creates files and folders that only the account running SecureBank can open.
 */
final class SecureFiles {

    // CWE-378 (Creation of Temporary File With Insecure Permissions): every file and folder the
    // bank writes (statements, temporary files, the audit log) is created owner-only.
    //  - On Linux and macOS, the permissions are passed to the create call itself, so the file is
    //    never visible to other users, not even for an instant.
    //  - On Windows, the folder is created inside the user's private temp folder and its access
    //    list is immediately replaced with one entry for the owner; files are then only ever
    //    created inside that locked-down folder, so they are never exposed either.
    // Temporary file names come from Files.createTempFile(), which picks unpredictable names, so
    // another program can't guess the name and create or read it first.
    private static final Set<String> VIEWS = FileSystems.getDefault().supportedFileAttributeViews();
    private static final boolean POSIX = VIEWS.contains("posix");
    private static final boolean ACL = VIEWS.contains("acl");

    private SecureFiles() {
    }

    static Path createOwnerOnlyTempDirectory(String prefix) throws IOException {
        if (POSIX) {
            return Files.createTempDirectory(prefix, ownerOnly("rwx------"));
        }
        Path directory = Files.createTempDirectory(prefix);
        restrictToOwner(directory, true);
        return directory;
    }

    static Path createOwnerOnlyDirectory(Path directory) throws IOException {
        if (Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            return directory;
        }
        if (POSIX) {
            return Files.createDirectory(directory, ownerOnly("rwx------"));
        }
        Files.createDirectory(directory);
        restrictToOwner(directory, true);
        return directory;
    }

    static Path createOwnerOnlyTempFile(Path directory, String prefix, String suffix) throws IOException {
        if (POSIX) {
            return Files.createTempFile(directory, prefix, suffix, ownerOnly("rw-------"));
        }
        Path file = Files.createTempFile(directory, prefix, suffix);
        restrictToOwner(file, false);
        return file;
    }

    static Path createOwnerOnlyFile(Path file) throws IOException {
        if (POSIX) {
            return Files.createFile(file, ownerOnly("rw-------"));
        }
        Files.createFile(file);
        restrictToOwner(file, false);
        return file;
    }

    /** A short description of who can open {@code path}, for the demo output. */
    static String describeAccess(Path path) throws IOException {
        if (POSIX) {
            return "POSIX permissions " + PosixFilePermissions.toString(
                    Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS));
        }
        if (ACL) {
            AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            UserPrincipal owner = view.getOwner();
            List<AclEntry> entries = view.getAcl();
            long ownerEntries = entries.stream().filter(entry -> entry.principal().equals(owner)).count();
            return "Windows access list with " + entries.size() + " entr" + (entries.size() == 1 ? "y" : "ies")
                    + (ownerEntries == entries.size() ? ", all for the file's owner" : ", NOT all for the owner");
        }
        return "unknown (no permission model available)";
    }

    static void deleteRecursively(Path root) throws IOException {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        // Files.walk does not follow symbolic links, so this can't wander outside root.
        List<Path> paths;
        try (Stream<Path> walk = Files.walk(root)) {
            paths = walk.sorted(Comparator.reverseOrder()).toList();
        }
        for (Path path : paths) {
            Files.deleteIfExists(path);
        }
    }

    private static FileAttribute<Set<PosixFilePermission>> ownerOnly(String permissions) {
        return PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(permissions));
    }

    private static void restrictToOwner(Path path, boolean directory) throws IOException {
        if (ACL) {
            AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            AclEntry.Builder ownerEntry = AclEntry.newBuilder()
                    .setType(AclEntryType.ALLOW)
                    .setPrincipal(view.getOwner())
                    .setPermissions(EnumSet.allOf(AclEntryPermission.class));
            if (directory) {
                ownerEntry.setFlags(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT);
            }
            view.setAcl(List.of(ownerEntry.build()));
            return;
        }
        // Last resort for file systems with neither model: owner-only via java.io.File.
        File file = path.toFile();
        boolean restricted = file.setReadable(false, false) & file.setReadable(true, true)
                & file.setWritable(false, false) & file.setWritable(true, true);
        if (directory) {
            restricted &= file.setExecutable(false, false) & file.setExecutable(true, true);
        }
        if (!restricted) {
            // CWE-431: don't carry on with a file we couldn't protect.
            throw new IOException("Could not restrict access to " + path.getFileName());
        }
    }
}
