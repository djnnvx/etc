/*
    confirms that everything works
*/

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H

int main(int argc, char ** argv)
{
FT_Library library; /* handle to library */
FT_Face face; /* handle to face object */
FT_Error error; /* hande to error*/


error = FT_Init_FreeType(&library);
if (error) { printf("Could not load the library."); }

char * filename = argv[1];
error = FT_New_Face(library, filename, 0, &face); /* create face object */
if (error) { printf("Could not create a face."); return 1; }

// Cleanup
FT_Done_Face(face);
FT_Done_FreeType(library);
return 0;
}
