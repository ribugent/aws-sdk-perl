package Paws::ComprehendMedical::ICD10CMConcept;
  use Moose;
  has Code => (is => 'ro', isa => 'Str');
  has Description => (is => 'ro', isa => 'Str');
  has Score => (is => 'ro', isa => 'Num');
1;

### main pod documentation begin ###

=head1 NAME

Paws::ComprehendMedical::ICD10CMConcept

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::ComprehendMedical::ICD10CMConcept object:

  $service_obj->Method(Att1 => { Code => $value, ..., Score => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::ComprehendMedical::ICD10CMConcept object:

  $result = $service_obj->Method(...);
  $result->Att1->Code

=head1 DESCRIPTION

The ICD-10-CM concepts that the entity could refer to, along with a
score indicating the likelihood of the match.

=head1 ATTRIBUTES


=head2 Code => Str

  The ICD-10-CM code that identifies the concept found in the knowledge
base from the Centers for Disease Control.


=head2 Description => Str

  The long description of the ICD-10-CM code in the ontology.


=head2 Score => Num

  The level of confidence that Amazon Comprehend Medical has that the
entity is accurately linked to an ICD-10-CM concept.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::ComprehendMedical>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

