class Tag(db.Model):
    __tablename__ = 'Tag'
    TagID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    TagContent = db.Column(db.String(30))


class TagLink(db.Model):
    __tablename__ = 'TagLink'
    PieceID = db.Column(db.Integer, db.ForeignKey('Piece.PieceID'), primary_key=True)
    TagID = db.Column(db.Integer, db.ForeignKey('Tag.TagID'), primary_key=True)


class Anime(Piece):
    __tablename__ = 'Anime'
    AnimeSerial = db.Column(db.String(50))
    AnimeNum = db.Column(db.Integer)


class Novel(Piece):
    __tablename__ = 'Novel'
    NovelExtra = db.Column(db.String(300))


class Comic(Piece):
    __tablename__ = 'Comic'
    ComicBookName = db.Column(db.String(50))
    ComicBookPage = db.Column(db.Integer)