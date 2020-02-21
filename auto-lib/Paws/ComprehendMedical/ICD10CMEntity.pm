package Paws::ComprehendMedical::ICD10CMEntity;
  use Moose;
  has Attributes => (is => 'ro', isa => 'ArrayRef[Paws::ComprehendMedical::ICD10CMAttribute]');
  has BeginOffset => (is => 'ro', isa => 'Int');
  has Category => (is => 'ro', isa => 'Str');
  has EndOffset => (is => 'ro', isa => 'Int');
  has ICD10CMConcepts => (is => 'ro', isa => 'ArrayRef[Paws::ComprehendMedical::ICD10CMConcept]');
  has Id => (is => 'ro', isa => 'Int');
  has Score => (is => 'ro', isa => 'Num');
  has Text => (is => 'ro', isa => 'Str');
  has Traits => (is => 'ro', isa => 'ArrayRef[Paws::ComprehendMedical::ICD10CMTrait]');
  has Type => (is => 'ro', isa => 'Str');
1;

### main pod documentation begin ###

=head1 NAME

Paws::ComprehendMedical::ICD10CMEntity

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::ComprehendMedical::ICD10CMEntity object:

  $service_obj->Method(Att1 => { Attributes => $value, ..., Type => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::ComprehendMedical::ICD10CMEntity object:

  $result = $service_obj->Method(...);
  $result->Att1->Attributes

=head1 DESCRIPTION

The collection of medical entities extracted from the input text and
their associated information. For each entity, the response provides
the entity text, the entity category, where the entity text begins and
ends, and the level of confidence that Amazon Comprehend Medical has in
the detection and analysis. Attributes and traits of the entity are
also returned.

=head1 ATTRIBUTES


=head2 Attributes => ArrayRef[L<Paws::ComprehendMedical::ICD10CMAttribute>]

  The detected attributes that relate to the entity. An extracted segment
of the text that is an attribute of an entity, or otherwise related to
an entity, such as the nature of a medical condition.


=head2 BeginOffset => Int

  The 0-based character offset in the input text that shows where the
entity begins. The offset returns the UTF-8 code point in the string.


=head2 Category => Str

  The category of the entity. InferICD10CM detects entities in the
C<MEDICAL_CONDITION> category.


=head2 EndOffset => Int

  The 0-based character offset in the input text that shows where the
entity ends. The offset returns the UTF-8 code point in the string.


=head2 ICD10CMConcepts => ArrayRef[L<Paws::ComprehendMedical::ICD10CMConcept>]

  The ICD-10-CM concepts that the entity could refer to, along with a
score indicating the likelihood of the match.


=head2 Id => Int

  The numeric identifier for the entity. This is a monotonically
increasing id unique within this response rather than a global unique
identifier.


=head2 Score => Num

  The level of confidence that Amazon Comprehend Medical has in the
accuracy of the detection.


=head2 Text => Str

  The segment of input text that is matched to the detected entity.


=head2 Traits => ArrayRef[L<Paws::ComprehendMedical::ICD10CMTrait>]

  Provides Contextual information for the entity. The traits recognized
by InferICD10CM are C<DIAGNOSIS>, C<SIGN>, C<SYMPTOM>, and C<NEGATION.>


=head2 Type => Str

  Describes the specific type of entity with category of entities.
InferICD10CM detects entities of the type C<DX_NAME>.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::ComprehendMedical>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

